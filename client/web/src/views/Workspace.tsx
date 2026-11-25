import { useEffect, useRef, useState } from "react";
import type { EditorViewModel } from "../viewmodels/EditorViewModel";
import type { SyncState } from "../viewmodels/SyncController";
import { useViewModel } from "../viewmodels/ViewModel";
import type { WorkspaceViewModel } from "../viewmodels/WorkspaceViewModel";
import empty from "../art/empty.webp";
import { Editor } from "./Editor";
import { Modal } from "./Modal";
import { RecoveryKitCard } from "./RecoveryKitCard";

const DAY = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const TIME = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });
const FULL = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function when(ms: number): string {
  const date = new Date(ms);
  return date.toDateString() === new Date().toDateString() ? TIME.format(date) : DAY.format(date);
}

function syncLabel(sync: SyncState): string {
  switch (sync.phase) {
    case "syncing":
      return "Syncing…";
    case "offline":
      return sync.pending > 0 ? `Offline · ${sync.pending} to send` : "Offline";
    case "error":
      return "Sync problem";
    case "revoked":
      return "Device removed";
    case "idle":
      return sync.pending > 0 ? `${sync.pending} to send` : "Synced";
  }
}

/** The bar above an open note: back, folder, attach, delete. */
function NoteBar({ workspace, editor, folders }: { workspace: WorkspaceViewModel; editor: EditorViewModel; folders: string[] }) {
  const state = useViewModel(editor);
  const picker = useRef<HTMLInputElement>(null);
  // Typed text is only a draft until the field is left or Enter is pressed.
  const [folder, setFolder] = useState(state.folder);
  useEffect(() => setFolder(state.folder), [state.folder]);

  return (
    <header>
      <button className="back" onClick={() => void workspace.select(null)}>
        ‹ Notes
      </button>
      <input
        className="folder"
        aria-label="Folder"
        placeholder="No folder"
        title="Folder of this note, for example Work/Plans"
        list="folders"
        value={folder}
        onChange={(e) => setFolder(e.target.value)}
        onBlur={() => editor.setFolder(folder)}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
      />
      <datalist id="folders">
        {folders.map((path) => (
          <option key={path} value={path} />
        ))}
      </datalist>
      <span className="spacer" />
      <input
        ref={picker}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          editor.attachFiles([...(e.target.files ?? [])], null);
          e.target.value = "";
        }}
      />
      <button onClick={() => picker.current?.click()} title="Images, audio, video or any other file. You can also paste or drop them into the note.">
        Attach
      </button>
      <button
        className="danger"
        onClick={() => {
          if (window.confirm("Delete this note on all your devices?")) void workspace.deleteSelected();
        }}
      >
        Delete note
      </button>
    </header>
  );
}

export function Workspace({ workspace }: { workspace: WorkspaceViewModel }) {
  const state = useViewModel(workspace);
  const sync = useViewModel(workspace.sync);
  const [menuOpen, setMenuOpen] = useState(false);
  const notes = workspace.visibleNotes;
  const folders = workspace.folders;

  const choose = (dialog: "devices" | "recovery" | "sign-out") => {
    setMenuOpen(false);
    workspace.open(dialog);
  };

  return (
    <div className={`workspace${state.selectedId ? " has-note" : ""}`}>
      <aside className="sidebar">
        <header>
          <h1 className="brand">
            Notes <span aria-hidden="true">✿</span>
          </h1>
          <span className={`pill ${sync.phase}`} title={sync.problem ?? undefined}>
            {syncLabel(sync)}
          </span>
          <div className="menu">
            <button className="icon" aria-label="Menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>
              ⋯
            </button>
            {menuOpen && (
              <ul role="menu">
                <li>
                  <button role="menuitem" onClick={() => choose("devices")}>
                    Devices
                  </button>
                </li>
                <li>
                  <button role="menuitem" onClick={() => choose("recovery")}>
                    Recovery kit
                  </button>
                </li>
                <li>
                  <button role="menuitem" onClick={() => choose("sign-out")}>
                    Sign out
                  </button>
                </li>
              </ul>
            )}
          </div>
        </header>

        <div className="search">
          <input type="search" placeholder="Search" aria-label="Search notes" value={state.query} onChange={(e) => workspace.setQuery(e.target.value)} />
          <button className="primary" onClick={() => void workspace.createNote()}>
            New
          </button>
        </div>

        {sync.problem && <p className="problem">{sync.problem}</p>}
        {state.problem && !state.dialog && (
          <p className="problem" role="alert">
            {state.problem}{" "}
            <button className="link" onClick={() => workspace.dismissProblem()}>
              Dismiss
            </button>
          </p>
        )}

        {folders.length > 0 && (
          <ul className="folders" aria-label="Folders">
            <li>
              <button aria-current={state.folder === null} onClick={() => workspace.showFolder(null)}>
                All notes
              </button>
            </li>
            {folders.map((path) => (
              <li key={path}>
                <button
                  aria-current={state.folder === path}
                  className={`depth-${Math.min(path.split("/").length - 1, 4)}`}
                  onClick={() => workspace.showFolder(path)}
                >
                  {path.split("/").at(-1)}
                </button>
              </li>
            ))}
          </ul>
        )}

        <ul className="notes">
          {notes.map((note) => (
            <li key={note.note_id}>
              <button aria-current={note.note_id === state.selectedId} onClick={() => void workspace.select(note.note_id)}>
                <strong>{note.title || "Untitled"}</strong>
                <span>
                  <time dateTime={new Date(note.updated_ms).toISOString()}>{when(note.updated_ms)}</time> {note.preview}
                </span>
              </button>
            </li>
          ))}
          {notes.length === 0 && <li className="muted empty">{state.query ? "No note matches." : "No notes yet. Write the first one ✿"}</li>}
        </ul>
      </aside>

      <section className="pane">
        {state.editor ? (
          <>
            <NoteBar key={`bar-${state.editor.state.noteId}`} workspace={workspace} editor={state.editor} folders={folders} />
            <Editor key={state.editor.state.noteId} editor={state.editor} />
          </>
        ) : (
          <div className="placeholder">
            <img src={empty} alt="" />
            <p className="muted">Pick a note, or start a new one ✿</p>
          </div>
        )}
      </section>

      {state.dialog === "devices" && (
        <Modal title="Devices" onClose={() => workspace.close()}>
          <p className="muted">Every device that can read your notes. Remove one you no longer use or have lost.</p>
          {state.problem && <p className="problem">{state.problem}</p>}
          {!state.devices && !state.problem && <p className="muted">Loading…</p>}
          <ul className="devices">
            {state.devices?.map((device) => (
              <li key={device.device_id}>
                <div>
                  <strong>{device.name}</strong> {device.current && <span className="pill idle">This device</span>}
                  <br />
                  <span className="muted">Last seen {FULL.format(new Date(device.last_seen_at))}</span>
                </div>
                {!device.current && (
                  <button className="danger" onClick={() => void workspace.revokeDevice(device.device_id)}>
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        </Modal>
      )}

      {state.dialog === "recovery" && (
        <Modal title="Recovery kit" onClose={() => workspace.close()}>
          <p>
            With the account ID and these 24 words you can open your notes on a new device. Anyone else who has them can read your notes
            too.
          </p>
          {state.kit ? (
            <RecoveryKitCard kit={state.kit} />
          ) : (
            <div className="actions">
              <button className="primary" onClick={() => workspace.revealRecoveryKit()}>
                Show the words
              </button>
            </div>
          )}
        </Modal>
      )}

      {state.dialog === "sign-out" && (
        <Modal title="Sign out" onClose={() => workspace.close()}>
          <p>This removes your notes and keys from this browser. To come back you need your recovery kit.</p>
          {sync.pending > 0 && <p className="problem">{sync.pending} changes have not reached the server yet and would be lost.</p>}
          <div className="actions">
            <button onClick={() => workspace.close()}>Cancel</button>
            <button className="danger" onClick={() => void workspace.signOut()}>
              Sign out
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
