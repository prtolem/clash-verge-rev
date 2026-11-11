use crate::config::MixedPort;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use reqwest::{
    Client, Proxy, StatusCode,
    header::{HeaderMap, HeaderValue, USER_AGENT},
};
use sha2::{Digest as _, Sha256};
use smartstring::alias::String;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use sysproxy::Sysproxy;
use tauri::Url;

const HWID_HEADER: &str = "x-hwid";
const DEVICE_OS_HEADER: &str = "x-device-os";
const OS_VERSION_HEADER: &str = "x-ver-os";
const DEVICE_MODEL_HEADER: &str = "x-device-model";

static SUBSCRIPTION_DEVICE_HEADERS: OnceLock<HeaderMap> = OnceLock::new();

#[derive(Clone, Default)]
struct RequestHeaders {
    user_agent: Option<String>,
    additional: HeaderMap,
}

impl RequestHeaders {
    const fn new(user_agent: Option<String>, additional: HeaderMap) -> Self {
        Self { user_agent, additional }
    }
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> Option<std::string::String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = std::string::String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg(target_os = "macos")]
fn platform_machine_id() -> Option<std::string::String> {
    let output = command_output("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?;
    output.lines().find_map(|line| {
        let (_, value) = line.split_once("\"IOPlatformUUID\"")?;
        let (_, value) = value.split_once('=')?;
        let value = value.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

#[cfg(target_os = "windows")]
fn platform_machine_id() -> Option<std::string::String> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .ok()?
        .get_value::<std::string::String, _>("MachineGuid")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(target_os = "linux")]
fn platform_machine_id() -> Option<std::string::String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok().map(|value| value.trim().to_owned()))
        .filter(|value| !value.is_empty())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn platform_machine_id() -> Option<std::string::String> {
    None
}

fn fallback_machine_id() -> std::string::String {
    format!(
        "{}:{}:{}",
        gethostname::gethostname().to_string_lossy(),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn derive_hwid(source: &str) -> std::string::String {
    let digest = Sha256::digest(source.as_bytes());
    let mut hwid = std::string::String::with_capacity(16);
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for byte in digest.iter().take(8) {
        hwid.push(HEX[(byte >> 4) as usize] as char);
        hwid.push(HEX[(byte & 0x0f) as usize] as char);
    }

    hwid
}

fn device_hwid() -> std::string::String {
    let source = platform_machine_id().unwrap_or_else(fallback_machine_id);
    derive_hwid(&source)
}

const fn device_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

#[cfg(target_os = "linux")]
fn os_release_value(key: &str) -> Option<std::string::String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    contents.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim().trim_matches('"').to_owned())
    })
}

#[cfg(target_os = "windows")]
fn windows_version_value(name: &str) -> Option<std::string::String> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
        .ok()?
        .get_value::<std::string::String, _>(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn os_version() -> std::string::String {
    #[cfg(target_os = "macos")]
    if let Some(value) = command_output("sw_vers", &["-productVersion"]) {
        return value;
    }

    #[cfg(target_os = "windows")]
    if let Some(value) = windows_version_value("DisplayVersion").or_else(|| windows_version_value("CurrentBuild")) {
        return value;
    }

    #[cfg(target_os = "linux")]
    if let Some(value) = os_release_value("VERSION_ID") {
        return value;
    }

    std::env::consts::OS.to_owned()
}

fn device_model() -> std::string::String {
    #[cfg(target_os = "macos")]
    if let Some(value) = command_output("sysctl", &["-n", "hw.model"]) {
        return value;
    }

    #[cfg(target_os = "windows")]
    if let Some(value) = windows_version_value("ProductName") {
        return value;
    }

    #[cfg(target_os = "linux")]
    if let Some(value) = std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| os_release_value("PRETTY_NAME"))
    {
        return value;
    }

    format!("{} {}", device_os(), std::env::consts::ARCH)
}

fn safe_header_value(value: &str, fallback: &'static str) -> HeaderValue {
    let sanitized: std::string::String = value
        .chars()
        .filter(|character| character.is_ascii_graphic() || *character == ' ')
        .take(128)
        .collect();
    HeaderValue::from_str(if sanitized.is_empty() { fallback } else { &sanitized })
        .unwrap_or_else(|_| HeaderValue::from_static(fallback))
}

fn subscription_device_headers() -> HeaderMap {
    SUBSCRIPTION_DEVICE_HEADERS
        .get_or_init(|| {
            let mut headers = HeaderMap::new();
            headers.insert(HWID_HEADER, safe_header_value(&device_hwid(), "unknown-device"));
            headers.insert(DEVICE_OS_HEADER, HeaderValue::from_static(device_os()));
            headers.insert(
                OS_VERSION_HEADER,
                safe_header_value(&os_version(), std::env::consts::OS),
            );
            headers.insert(DEVICE_MODEL_HEADER, safe_header_value(&device_model(), "Desktop"));
            headers
        })
        .clone()
}

#[derive(Debug)]
pub struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl HttpResponse {
    const fn new(status: StatusCode, headers: HeaderMap, body: String) -> Self {
        Self { status, headers, body }
    }

    pub const fn status(&self) -> StatusCode {
        self.status
    }

    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn text(&self) -> &str {
        &self.body
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyType {
    None,
    Localhost,
    System,
}

#[derive(Debug, Clone, Copy)]
enum TlsRootMode {
    PlatformVerifier,
    StaticWebpkiRoots,
}

pub struct NetworkManager;

impl NetworkManager {
    pub const fn new() -> Self {
        Self
    }

    fn build_client(
        &self,
        proxy_url: Option<std::string::String>,
        default_headers: HeaderMap,
        accept_invalid_certs: bool,
        timeout_secs: Option<u64>,
        tls_root_mode: TlsRootMode,
    ) -> Result<Client> {
        let mut builder = Client::builder()
            .tls_backend_rustls()
            .redirect(reqwest::redirect::Policy::limited(10))
            .tcp_keepalive(Duration::from_secs(60))
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(None);

        if matches!(tls_root_mode, TlsRootMode::StaticWebpkiRoots) {
            builder = builder.tls_backend_preconfigured(Self::build_static_webpki_tls_config()?);
        }

        // 设置代理
        if let Some(proxy_str) = proxy_url {
            let proxy = Proxy::all(proxy_str)?;
            builder = builder.proxy(proxy);
        } else {
            builder = builder.no_proxy();
        }

        builder = builder.default_headers(default_headers);

        // SSL/TLS
        if accept_invalid_certs {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        // 超时设置
        if let Some(secs) = timeout_secs {
            builder = builder
                .timeout(Duration::from_secs(secs))
                .connect_timeout(Duration::from_secs(secs.min(30)));
        }

        Ok(builder.build()?)
    }

    fn build_static_webpki_tls_config() -> Result<rustls::ClientConfig> {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(root_store)
                .with_no_client_auth();

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }

    fn should_retry_with_static_webpki_roots(err: &anyhow::Error) -> bool {
        if err.chain().any(Self::is_legacy_tls_protocol_error) {
            return false;
        }

        err.chain().any(|e| {
            let msg = e.to_string().to_ascii_lowercase();
            [
                "certificate",
                "cert",
                "tls",
                "ssl",
                "rustls",
                "webpki",
                "revocation",
                "ocsp",
                "crl",
                "issuer",
                "unknownissuer",
            ]
            .iter()
            .any(|kw| msg.contains(kw))
        })
    }

    fn context_reqwest_error(err: reqwest::Error, context: &'static str) -> anyhow::Error {
        let legacy_tls = Self::is_legacy_tls_protocol_error(&err);
        let err = anyhow::Error::new(err).context(context);

        if legacy_tls {
            err.context("Subscription server uses legacy TLS; only TLS 1.2/1.3 is supported. TLS 1.0/1.1 is insecure")
        } else {
            err
        }
    }

    fn is_legacy_tls_protocol_error(err: &(dyn std::error::Error + 'static)) -> bool {
        let detail = format!("{err:#?}").to_ascii_lowercase();
        detail.contains("protocolversion") || detail.contains("protocol version")
    }

    async fn get_with_tls_mode(
        &self,
        url: &str,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        request_headers: RequestHeaders,
        accept_invalid_certs: bool,
        tls_root_mode: TlsRootMode,
    ) -> Result<HttpResponse> {
        let mut parsed = Url::parse(url)?;
        let mut extra_headers = HeaderMap::new();

        if !parsed.username().is_empty() {
            let username = percent_encoding::percent_decode_str(parsed.username())
                .decode_utf8_lossy()
                .into_owned();
            let password = percent_encoding::percent_decode_str(parsed.password().unwrap_or_default())
                .decode_utf8_lossy()
                .into_owned();
            let auth_str = format!("{}:{}", username, password);
            let encoded = general_purpose::STANDARD.encode(auth_str);
            extra_headers.insert("Authorization", HeaderValue::from_str(&format!("Basic {}", encoded))?);
        }

        parsed.set_username("").ok();
        parsed.set_password(None).ok();

        // 创建请求
        let client = self
            .create_request_with_tls_mode(
                proxy_type,
                timeout_secs,
                request_headers,
                accept_invalid_certs,
                tls_root_mode,
            )
            .await?;

        let mut request_builder = client.get(parsed);

        for (key, value) in extra_headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        let response = match request_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(Self::context_reqwest_error(e, "Request failed"));
            }
        };

        let status = response.status();
        let headers = response.headers().to_owned();
        let body = match response.text().await {
            Ok(text) => text.into(),
            Err(e) => {
                return Err(Self::context_reqwest_error(e, "Failed to read response body"));
            }
        };

        Ok(HttpResponse::new(status, headers, body))
    }

    async fn create_request_with_tls_mode(
        &self,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        request_headers: RequestHeaders,
        accept_invalid_certs: bool,
        tls_root_mode: TlsRootMode,
    ) -> Result<Client> {
        let proxy_url: Option<std::string::String> = match proxy_type {
            ProxyType::None => None,
            ProxyType::Localhost => {
                let port = MixedPort::desired().await;
                Some(format!("http://127.0.0.1:{port}"))
            }
            ProxyType::System => {
                if let Ok(p @ Sysproxy { enable: true, .. }) = Sysproxy::get_system_proxy() {
                    Some(format!("http://{}:{}", p.host, p.port))
                } else {
                    None
                }
            }
        };

        let RequestHeaders {
            user_agent,
            additional: mut headers,
        } = request_headers;

        // 设置 User-Agent
        if let Some(ua) = user_agent {
            headers.insert(USER_AGENT, HeaderValue::from_str(ua.as_str())?);
        } else {
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&format!("clash-verge/v{}", env!("CARGO_PKG_VERSION")))?,
            );
        }

        self.build_client(proxy_url, headers, accept_invalid_certs, timeout_secs, tls_root_mode)
    }

    pub async fn get(
        &self,
        url: &str,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        user_agent: Option<String>,
        accept_invalid_certs: bool,
    ) -> Result<HttpResponse> {
        let platform_result = self
            .get_with_tls_mode(
                url,
                proxy_type,
                timeout_secs,
                RequestHeaders::new(user_agent.clone(), HeaderMap::new()),
                accept_invalid_certs,
                TlsRootMode::PlatformVerifier,
            )
            .await;

        match platform_result {
            Ok(response) => Ok(response),
            Err(err) if !accept_invalid_certs && Self::should_retry_with_static_webpki_roots(&err) => self
                .get_with_tls_mode(
                    url,
                    proxy_type,
                    timeout_secs,
                    RequestHeaders::new(user_agent, HeaderMap::new()),
                    accept_invalid_certs,
                    TlsRootMode::StaticWebpkiRoots,
                )
                .await
                .map_err(|fallback_err| {
                    fallback_err.context("static webpki roots fallback failed after platform TLS verifier failed")
                }),
            Err(err) => Err(err),
        }
    }

    /// Downloads a subscription while identifying this device to panels that enforce HWID limits.
    pub async fn get_subscription(
        &self,
        url: &str,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        user_agent: Option<String>,
        accept_invalid_certs: bool,
    ) -> Result<HttpResponse> {
        let platform_result = self
            .get_with_tls_mode(
                url,
                proxy_type,
                timeout_secs,
                RequestHeaders::new(user_agent.clone(), subscription_device_headers()),
                accept_invalid_certs,
                TlsRootMode::PlatformVerifier,
            )
            .await;

        match platform_result {
            Ok(response) => Ok(response),
            Err(err) if !accept_invalid_certs && Self::should_retry_with_static_webpki_roots(&err) => self
                .get_with_tls_mode(
                    url,
                    proxy_type,
                    timeout_secs,
                    RequestHeaders::new(user_agent, subscription_device_headers()),
                    accept_invalid_certs,
                    TlsRootMode::StaticWebpkiRoots,
                )
                .await
                .map_err(|fallback_err| {
                    fallback_err.context("static webpki roots fallback failed after platform TLS verifier failed")
                }),
            Err(err) => Err(err),
        }
    }

    async fn get_bytes_with_tls_mode(
        &self,
        url: &str,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        max_bytes: usize,
        tls_root_mode: TlsRootMode,
    ) -> Result<Vec<u8>> {
        let client = self
            .create_request_with_tls_mode(
                proxy_type,
                timeout_secs,
                RequestHeaders::default(),
                false,
                tls_root_mode,
            )
            .await?;

        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|e| Self::context_reqwest_error(e, "Request failed"))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("request failed with status {status}");
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Self::context_reqwest_error(e, "Failed to read response body"))?
        {
            if body.len() + chunk.len() > max_bytes {
                anyhow::bail!("response exceeded the {max_bytes} byte limit");
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }

    /// Downloads a binary body, mirroring the TLS fallback of [`Self::get`].
    pub async fn get_bytes(
        &self,
        url: &str,
        proxy_type: ProxyType,
        timeout_secs: Option<u64>,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        let platform_result = self
            .get_bytes_with_tls_mode(url, proxy_type, timeout_secs, max_bytes, TlsRootMode::PlatformVerifier)
            .await;

        match platform_result {
            Ok(body) => Ok(body),
            Err(err) if Self::should_retry_with_static_webpki_roots(&err) => self
                .get_bytes_with_tls_mode(url, proxy_type, timeout_secs, max_bytes, TlsRootMode::StaticWebpkiRoots)
                .await
                .map_err(|fallback_err| {
                    fallback_err.context("static webpki roots fallback failed after platform TLS verifier failed")
                }),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn derived_hwid_matches_remnawave_format() {
        let hwid = derive_hwid("stable-machine-identifier");

        assert_eq!(hwid.len(), 16);
        assert!(hwid.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(hwid, derive_hwid("stable-machine-identifier"));
        assert_ne!(hwid, derive_hwid("another-machine-identifier"));
    }

    #[test]
    fn subscription_headers_include_device_identity() {
        let headers = subscription_device_headers();
        let hwid = headers
            .get(HWID_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        assert!((10..=64).contains(&hwid.len()));
        assert!(
            hwid.chars()
                .all(|character| character.is_ascii_alphanumeric() || matches!(character, '=' | '-'))
        );
        assert!(headers.contains_key(DEVICE_OS_HEADER));
        assert!(headers.contains_key(OS_VERSION_HEADER));
        assert!(headers.contains_key(DEVICE_MODEL_HEADER));
    }

    #[tokio::test]
    async fn subscription_request_sends_hwid_headers() -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(std::string::String::from_utf8_lossy(&request).into_owned())
                .map_err(|_| std::io::Error::other("return captured request"))?;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
            Ok(())
        });

        let response = NetworkManager::new()
            .get_subscription(
                &format!("http://{address}/subscription"),
                ProxyType::None,
                Some(5),
                Some("clash-verge/test".into()),
                false,
            )
            .await?;
        let request = request_rx.recv()?.to_ascii_lowercase();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(request.contains("x-hwid: "));
        assert!(request.contains("x-device-os: "));
        assert!(request.contains("x-ver-os: "));
        assert!(request.contains("x-device-model: "));
        assert!(request.contains("user-agent: clash-verge/test"));
        server
            .join()
            .map_err(|_| std::io::Error::other("test server thread panicked"))??;
        Ok(())
    }
}
