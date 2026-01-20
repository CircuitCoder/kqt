use clap::Args;
use kqt_lib::{config::Config, tunnel::IfaceSetup};
use std::path::PathBuf;

#[derive(Args)]
pub struct Server {
    /// Path to the config file
    config: PathBuf,

    #[arg(default_value = "kqt0")]
    /// Name of the iface
    name: String,
}

impl Server {
    pub async fn run(self) -> anyhow::Result<!> {
        let s = std::fs::read_to_string(&self.config)?;
        let cfg: Config = toml::de::from_str(&s)?;

        // TODO: move this into config parsing verification, and use thiserror
        if cfg.connect_to.is_empty() && cfg.listen.is_none() {
            tracing::error!("At least one of listen or connect_to must be specified.");
            std::process::exit(1);
        }

        let iface = IfaceSetup::Create(self.name);
        kqt_lib::tunnel::run(iface, cfg).await
    }
}
