//! The web adapter: the shared core compiled to WebAssembly.
//!
//! Two thin layers and nothing else:
//! * [`WebPlatform`] implements the six HAL ports by calling a JavaScript
//!   object (`app/hal.js`) that wraps fetch, IndexedDB and Web Crypto.
//! * [`NotesApp`] exposes the core to the page. Structured values cross the
//!   boundary as JSON text.
#![forbid(unsafe_code)]

use js_sys::{Array, Reflect, Uint8Array};
use notes_core::hal::{
    Entropy, FileStore, HalError, HttpRequest, HttpResponse, HttpTransport, NetworkMonitor, SecureStore, TimeSource,
};
use notes_core::{Core, CoreError};
use std::collections::BTreeMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
extern "C" {
    /// The object exported by `app/hal.js`.
    pub type JsHal;

    #[wasm_bindgen(method, catch)]
    async fn http(this: &JsHal, method: &str, url: &str, headers: Array, body: Option<Uint8Array>) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = fileRead)]
    async fn file_read(this: &JsHal, name: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = fileWrite)]
    async fn file_write(this: &JsHal, name: &str, data: Uint8Array) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = fileRemove)]
    async fn file_remove(this: &JsHal, name: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = fileList)]
    async fn file_list(this: &JsHal, prefix: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = secretGet)]
    async fn secret_get(this: &JsHal, name: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = secretPut)]
    async fn secret_put(this: &JsHal, name: &str, data: Uint8Array) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = secretRemove)]
    async fn secret_remove(this: &JsHal, name: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, js_name = nowMs)]
    fn now_ms(this: &JsHal) -> f64;
    #[wasm_bindgen(method, js_name = isOnline)]
    fn is_online(this: &JsHal) -> bool;
    #[wasm_bindgen(method, catch, js_name = fillRandom)]
    fn fill_random(this: &JsHal, buffer: &mut [u8]) -> Result<(), JsValue>;
}

fn hal_error(value: JsValue) -> HalError {
    let message = value
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| value.as_string())
        .unwrap_or_else(|| "unknown error".into());
    HalError(message)
}

fn bytes_or_none(value: JsValue) -> Option<Vec<u8>> {
    value.dyn_into::<Uint8Array>().ok().map(|array| array.to_vec())
}

pub struct WebPlatform {
    hal: JsHal,
}

impl HttpTransport for WebPlatform {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HalError> {
        let headers = Array::new();
        for (name, value) in &request.headers {
            headers.push(&Array::of2(&JsValue::from_str(name), &JsValue::from_str(value)));
        }
        let body = request.body.as_deref().map(Uint8Array::from);
        let response = self.hal.http(request.method, &request.url, headers, body).await.map_err(hal_error)?;
        let get = |key: &str| Reflect::get(&response, &JsValue::from_str(key)).map_err(hal_error);
        let status = get("status")?.as_f64().ok_or_else(|| HalError("response without status".into()))? as u16;
        let mut headers = Vec::new();
        for pair in Array::from(&get("headers")?).iter() {
            let pair = Array::from(&pair);
            if let (Some(name), Some(value)) = (pair.get(0).as_string(), pair.get(1).as_string()) {
                headers.push((name.to_ascii_lowercase(), value));
            }
        }
        let body = bytes_or_none(get("body")?).unwrap_or_default();
        Ok(HttpResponse { status, headers, body })
    }
}

impl FileStore for WebPlatform {
    async fn file_read(&self, name: &str) -> Result<Option<Vec<u8>>, HalError> {
        self.hal.file_read(name).await.map(bytes_or_none).map_err(hal_error)
    }
    async fn file_write(&self, name: &str, data: &[u8]) -> Result<(), HalError> {
        self.hal.file_write(name, Uint8Array::from(data)).await.map(|_| ()).map_err(hal_error)
    }
    async fn file_remove(&self, name: &str) -> Result<(), HalError> {
        self.hal.file_remove(name).await.map(|_| ()).map_err(hal_error)
    }
    async fn file_list(&self, prefix: &str) -> Result<Vec<String>, HalError> {
        let names = self.hal.file_list(prefix).await.map_err(hal_error)?;
        Ok(Array::from(&names).iter().filter_map(|name| name.as_string()).collect())
    }
}

impl SecureStore for WebPlatform {
    async fn secret_get(&self, name: &str) -> Result<Option<Vec<u8>>, HalError> {
        self.hal.secret_get(name).await.map(bytes_or_none).map_err(hal_error)
    }
    async fn secret_put(&self, name: &str, data: &[u8]) -> Result<(), HalError> {
        self.hal.secret_put(name, Uint8Array::from(data)).await.map(|_| ()).map_err(hal_error)
    }
    async fn secret_remove(&self, name: &str) -> Result<(), HalError> {
        self.hal.secret_remove(name).await.map(|_| ()).map_err(hal_error)
    }
}

impl TimeSource for WebPlatform {
    fn now_ms(&self) -> i64 {
        self.hal.now_ms() as i64
    }
}

impl NetworkMonitor for WebPlatform {
    fn is_online(&self) -> bool {
        self.hal.is_online()
    }
}

impl Entropy for WebPlatform {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), HalError> {
        self.hal.fill_random(buffer).map_err(hal_error)
    }
}

/// A JavaScript `Error` with the core's stable `code` and, if the server
/// asked for a pause, `retryAfter` in seconds.
fn js_error(error: CoreError) -> JsValue {
    let js = js_sys::Error::new(&error.message);
    let _ = Reflect::set(&js, &JsValue::from_str("code"), &JsValue::from_str(&error.code));
    if let Some(seconds) = error.retry_after {
        let _ = Reflect::set(&js, &JsValue::from_str("retryAfter"), &JsValue::from_f64(f64::from(seconds)));
    }
    js.into()
}

fn json<T: serde::Serialize>(value: &T) -> JsValue {
    JsValue::from_str(&serde_json::to_string(value).unwrap_or_else(|_| "null".into()))
}

#[wasm_bindgen]
pub struct NotesApp {
    core: Rc<Core<WebPlatform>>,
}

/// Runs a core call as a JavaScript promise. The core is shared by reference
/// count, so the page may start another call while one is waiting.
macro_rules! promise {
    ($self:ident, |$core:ident| $body:expr) => {{
        let $core = $self.core.clone();
        future_to_promise(async move { $body.map_err(js_error) })
    }};
}

#[wasm_bindgen]
impl NotesApp {
    /// Loads the account and notes stored in this browser.
    pub async fn open(hal: JsHal) -> Result<NotesApp, JsValue> {
        let core = Core::open(WebPlatform { hal }).await.map_err(js_error)?;
        Ok(NotesApp { core: Rc::new(core) })
    }

    pub fn status(&self) -> JsValue {
        json(&self.core.status())
    }

    #[wasm_bindgen(js_name = createAccount)]
    pub fn create_account(&self, server_url: String, invite_code: String, device_name: String) -> js_sys::Promise {
        promise!(self, |core| core.create_account(&server_url, &invite_code, &device_name).await.map(|kit| json(&kit)))
    }

    pub fn recover(&self, server_url: String, account_id: String, phrase: String, device_name: String) -> js_sys::Promise {
        promise!(self, |core| core
            .recover(&server_url, &account_id, &phrase, &device_name)
            .await
            .map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = recoveryKit)]
    pub fn recovery_kit(&self) -> Result<JsValue, JsValue> {
        self.core.recovery_kit().map(|kit| json(&kit)).map_err(js_error)
    }

    #[wasm_bindgen(js_name = signOut)]
    pub fn sign_out(&self, revoke: bool) -> js_sys::Promise {
        promise!(self, |core| core.sign_out(revoke).await.map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = listDevices)]
    pub fn list_devices(&self) -> js_sys::Promise {
        promise!(self, |core| core.list_devices().await.map(|devices| json(&devices)))
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&self, device_id: String) -> js_sys::Promise {
        promise!(self, |core| core.revoke_device(&device_id).await.map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = listNotes)]
    pub fn list_notes(&self) -> JsValue {
        json(&self.core.list_notes())
    }

    /// The note as JSON, or `null` if it does not exist (any more).
    #[wasm_bindgen(js_name = getNote)]
    pub fn get_note(&self, note_id: &str) -> JsValue {
        json(&self.core.get_note(note_id))
    }

    #[wasm_bindgen(js_name = createNote)]
    pub fn create_note(&self, folder: String) -> js_sys::Promise {
        promise!(self, |core| core.create_note(&folder).await.map(|note| json(&note)))
    }

    /// `folder` is a path like "Work/Plans"; empty for no folder.
    #[wasm_bindgen(js_name = setFolder)]
    pub fn set_folder(&self, note_id: String, folder: String) -> js_sys::Promise {
        promise!(self, |core| core.set_folder(&note_id, &folder).await.map(|()| JsValue::UNDEFINED))
    }

    /// Encrypts `data` and adds it to the note as an attachment block.
    #[wasm_bindgen(js_name = addAttachment)]
    pub fn add_attachment(
        &self,
        note_id: String,
        after: Option<String>,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> js_sys::Promise {
        promise!(self, |core| core
            .add_attachment(&note_id, after.as_deref(), &name, &mime, &data)
            .await
            .map(|block| json(&block)))
    }

    /// The decrypted file of an attachment block, as a `Uint8Array`.
    pub fn attachment(&self, block_id: String) -> js_sys::Promise {
        promise!(self, |core| core
            .attachment(&block_id)
            .await
            .map(|bytes| JsValue::from(Uint8Array::from(bytes.as_slice()))))
    }

    #[wasm_bindgen(js_name = setTitle)]
    pub fn set_title(&self, note_id: String, title: String) -> js_sys::Promise {
        promise!(self, |core| core.set_title(&note_id, &title).await.map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = insertBlock)]
    pub fn insert_block(&self, note_id: String, after: Option<String>, kind: String, text: String) -> js_sys::Promise {
        promise!(self, |core| core
            .insert_block(&note_id, after.as_deref(), &kind, &text)
            .await
            .map(|block| json(&block)))
    }

    /// `attrs_json` is a JSON object of strings.
    #[wasm_bindgen(js_name = updateBlock)]
    pub fn update_block(&self, block_id: String, kind: String, text: String, attrs_json: String) -> js_sys::Promise {
        promise!(self, |core| {
            match serde_json::from_str::<BTreeMap<String, String>>(&attrs_json) {
                Ok(attrs) => core.update_block(&block_id, &kind, &text, attrs).await.map(|()| JsValue::UNDEFINED),
                Err(_) => Err(CoreError { code: "input".into(), message: "attributes must be a JSON object of strings".into(), retry_after: None }),
            }
        })
    }

    /// Moves a block behind `after`, or to the top of its note without it.
    #[wasm_bindgen(js_name = moveBlock)]
    pub fn move_block(&self, block_id: String, after: Option<String>) -> js_sys::Promise {
        promise!(self, |core| core.move_block(&block_id, after.as_deref()).await.map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = deleteBlock)]
    pub fn delete_block(&self, block_id: String) -> js_sys::Promise {
        promise!(self, |core| core.delete_block(&block_id).await.map(|()| JsValue::UNDEFINED))
    }

    #[wasm_bindgen(js_name = deleteNote)]
    pub fn delete_note(&self, note_id: String) -> js_sys::Promise {
        promise!(self, |core| core.delete_note(&note_id).await.map(|()| JsValue::UNDEFINED))
    }

    pub fn sync(&self) -> js_sys::Promise {
        promise!(self, |core| core.sync().await.map(|report| json(&report)))
    }

    /// Address and headers for the server's change notifications, as JSON,
    /// for the page to open the stream with.
    #[wasm_bindgen(js_name = eventsRequest)]
    pub fn events_request(&self) -> Result<JsValue, JsValue> {
        self.core.events_request().map(|request| json(&request)).map_err(js_error)
    }
}
