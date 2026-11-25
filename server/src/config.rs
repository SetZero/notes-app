//! Server configuration, loaded from a TOML file.

use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::BoxError;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub enrollment: EnrollmentConfig,
    #[serde(default)]
    pub oidc: Vec<OidcConfig>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_url: Option<String>,
    pub allow_plain_http: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub static_dir: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".parse().unwrap(),
            data_dir: PathBuf::from("./data"),
            database_url: None,
            allow_plain_http: false,
            trusted_proxies: Vec::new(),
            static_dir: None,
        }
    }
}

/// An address or an address range in CIDR form, e.g. "10.42.0.0/16".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits(ip: IpAddr) -> (u128, u8) {
            match ip {
                IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
                IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => (u128::from(u32::from(v4)), 32),
                    None => (u128::from(v6), 128),
                },
            }
        }
        let (net, net_len) = bits(self.addr);
        let (ip, ip_len) = bits(ip);
        if net_len != ip_len {
            return false;
        }
        let shift = u32::from(net_len - self.prefix.min(net_len));
        shift >= 128 || (net >> shift) == (ip >> shift)
    }
}

impl From<IpAddr> for IpNet {
    fn from(addr: IpAddr) -> Self {
        Self { addr, prefix: if addr.is_ipv4() { 32 } else { 128 } }
    }
}

impl TryFrom<String> for IpNet {
    type Error = String;
    fn try_from(text: String) -> Result<Self, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text.as_str(), None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("\"{text}\" is not an IP address or CIDR range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| format!("\"{text}\" has an invalid prefix length"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::IpNet;

    #[test]
    fn ranges_match_only_their_own_addresses() {
        let net = IpNet::try_from("10.42.0.0/16".to_string()).unwrap();
        assert!(net.contains("10.42.7.9".parse().unwrap()));
        assert!(net.contains("::ffff:10.42.7.9".parse().unwrap()));
        assert!(!net.contains("10.43.0.1".parse().unwrap()));
        assert!(!net.contains("fd00::1".parse().unwrap()));
        let one = IpNet::try_from("192.0.2.7".to_string()).unwrap();
        assert!(one.contains("192.0.2.7".parse().unwrap()));
        assert!(!one.contains("192.0.2.8".parse().unwrap()));
        let v6 = IpNet::try_from("fd00:42::/32".to_string()).unwrap();
        assert!(v6.contains("fd00:42:1::5".parse().unwrap()));
        assert!(!v6.contains("fd00:43::5".parse().unwrap()));
        assert!(IpNet::try_from("10.0.0.0/33".to_string()).is_err());
        assert!(IpNet::try_from("nonsense".to_string()).is_err());
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentMode {
    #[default]
    Invite,
    Oidc,
    Either,
}

impl EnrollmentMode {
    pub fn allows_invite(self) -> bool {
        matches!(self, Self::Invite | Self::Either)
    }
    pub fn allows_oidc(self) -> bool {
        matches!(self, Self::Oidc | Self::Either)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invite => "invite",
            Self::Oidc => "oidc",
            Self::Either => "either",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct EnrollmentConfig {
    pub mode: EnrollmentMode,
    pub invite_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// Short name clients use to pick the provider.
    pub id: String,
    /// Issuer URL exactly as the provider reports it in its discovery document.
    pub issuer: String,
    /// The `aud` every accepted ID token must carry.
    pub client_id: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Accepted signature algorithms. Symmetric algorithms and "none" are never accepted.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub required_claim: Option<RequiredClaim>,
    /// Only for local development and tests: allow an http:// issuer.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequiredClaim {
    pub name: String,
    pub value: String,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into()]
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_batch_blocks: usize,
    pub max_block_ciphertext_bytes: usize,
    pub max_request_bytes: usize,
    pub max_blob_bytes: u64,
    pub max_account_blob_bytes: u64,
    pub max_clock_skew_seconds: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_batch_blocks: 100,
            max_block_ciphertext_bytes: 65_536,
            max_request_bytes: 1_048_576,
            max_blob_bytes: 26_214_400,
            max_account_blob_bytes: 5 * 1024 * 1024 * 1024,
            max_clock_skew_seconds: 600,
        }
    }
}

pub const MIN_INVITE_CODE_LEN: usize = 16;

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, BoxError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
        let mut config: Config = toml::from_str(&text)?;
        if let Ok(code) = std::env::var("NOTES_SYNCD_INVITE_CODE") {
            config.enrollment.invite_code = Some(code);
        }
        Ok(config)
    }

    /// Refuses configurations that would be insecure or cannot work.
    pub fn validate(&self) -> Result<(), BoxError> {
        let mode = self.enrollment.mode;
        if mode.allows_invite() {
            match &self.enrollment.invite_code {
                Some(code) if code.len() >= MIN_INVITE_CODE_LEN => {}
                Some(_) => {
                    return Err(format!(
                        "enrollment.invite_code must have at least {MIN_INVITE_CODE_LEN} characters"
                    )
                    .into())
                }
                None if mode == EnrollmentMode::Invite => {
                    return Err("enrollment.mode is \"invite\" but no invite code is set \
                                (config or NOTES_SYNCD_INVITE_CODE)"
                        .into())
                }
                None => {}
            }
        }
        if mode == EnrollmentMode::Oidc && self.oidc.is_empty() {
            return Err("enrollment.mode is \"oidc\" but no [[oidc]] provider is configured".into());
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.oidc {
            if !seen.insert(&p.id) {
                return Err(format!("duplicate oidc provider id \"{}\"", p.id).into());
            }
            let https = p.issuer.starts_with("https://");
            let http = p.issuer.starts_with("http://");
            if !(https || (http && p.allow_insecure_http)) {
                return Err(format!("oidc provider \"{}\": issuer must be an https:// URL", p.id).into());
            }
            if p.client_id.is_empty() {
                return Err(format!("oidc provider \"{}\": client_id is empty", p.id).into());
            }
            if p.algorithms.is_empty() {
                return Err(format!("oidc provider \"{}\": no algorithms", p.id).into());
            }
            for alg in &p.algorithms {
                crate::oidc::parse_algorithm(alg)
                    .ok_or_else(|| format!("oidc provider \"{}\": algorithm \"{alg}\" is not allowed", p.id))?;
            }
        }
        if self.tls.is_none() && !self.server.allow_plain_http && !self.server.listen.ip().is_loopback() {
            return Err("no [tls] section: refusing to serve plain HTTP on a non-loopback address. \
                        Configure TLS, or set server.allow_plain_http = true if a reverse proxy \
                        terminates TLS in front of this server"
                .into());
        }
        if self.limits.max_batch_blocks == 0 || self.limits.max_block_ciphertext_bytes < 16 {
            return Err("limits are too small to be usable".into());
        }
        Ok(())
    }

    pub fn database_url(&self) -> String {
        match &self.server.database_url {
            Some(url) => url.clone(),
            None => {
                // "sqlite:<path>" without "//": otherwise a Windows drive letter
                // would be parsed as a host name. Characters that are special in
                // a URL are percent-encoded so any directory name works.
                let path = self.server.data_dir.join("notes.db");
                let mut encoded = String::new();
                for ch in path.to_string_lossy().chars() {
                    match ch {
                        '\\' => encoded.push('/'),
                        '%' | '?' | '#' | ' ' => encoded.push_str(&format!("%{:02X}", ch as u32)),
                        _ => encoded.push(ch),
                    }
                }
                format!("sqlite:{encoded}?mode=rwc")
            }
        }
    }
}
