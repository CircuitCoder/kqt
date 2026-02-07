use std::sync::Arc;

use kqt_lib::{config::Route, tunnel::IfaceSetup};

uniffi::setup_scaffolding!();

#[derive(uniffi::Object)]
struct Runtime(tokio::runtime::Runtime);

#[uniffi::export]
impl Runtime {
    #[uniffi::constructor]
    fn new() -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        Arc::new(Runtime(rt))
    }
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
#[uniffi(flat_error)]
pub enum ConfigParseError {
    #[error("Unable to parse config: {0}")]
    ParseError(String),
}

#[derive(uniffi::Object)]
struct ParsedConfig {
    cfg: kqt_lib::config::Config,
}

#[derive(uniffi::Record)]
struct SerializedRoute {
    to: String,
    via: String,
    metric: Option<u32>,
}

impl From<&Route> for SerializedRoute {
    fn from(route: &Route) -> Self {
        Self {
            to: route.to.to_string(),
            via: route.via.to_string(),
            metric: route.metric,
        }
    }
}

#[uniffi::export]
impl ParsedConfig {
    #[uniffi::constructor]
    fn parse(s: &str) -> Result<ParsedConfig, ConfigParseError> {
        let cfg: kqt_lib::config::Config = match toml::de::from_str(s) {
            Ok(c) => c,
            Err(e) => {
                return Err(ConfigParseError::ParseError(format!(
                    "Failed to parse config: {}",
                    e
                )));
            }
        };
        Ok(ParsedConfig { cfg })
    }

    fn address(&self) -> Vec<String> {
        self.cfg
            .address
            .iter()
            .map(|inet| inet.to_string())
            .collect()
    }

    fn routes(&self) -> Vec<SerializedRoute> {
        self.cfg
            .routes
            .iter()
            .map(|net| SerializedRoute::from(net))
            .collect()
    }

    fn mtu(&self) -> Option<u16> {
        self.cfg.mtu
    }

    fn start(&self, rt: Arc<Runtime>, fd: std::os::fd::RawFd, mtu: u16) -> BackendHandle {
        let cancel = kqt_lib::tunnel::CancellationToken::new();
        let corr =
            kqt_lib::tunnel::run(IfaceSetup::Fd { fd, mtu }, self.cfg.clone(), cancel.clone());
        let handle = rt.0.spawn(corr);

        BackendHandle {
            handle: std::sync::Mutex::new(Some(handle)),
            cancel,
        }
    }
}

#[derive(uniffi::Object)]
struct BackendHandle {
    handle: std::sync::Mutex<Option<tokio::task::JoinHandle<uniffi::deps::anyhow::Result<()>>>>,
    cancel: kqt_lib::tunnel::CancellationToken,
}

#[uniffi::export]
impl BackendHandle {
    fn stop(&self) {
        self.cancel.cancel();
    }

    async fn wait(&self) {
        // FIXME: does this temporary gets lifetime extension?
        let handle = self.handle.lock().unwrap().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }
}
