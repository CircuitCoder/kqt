#![feature(never_type, try_blocks, try_trait_v2, substr_range)]

mod keygen;
mod server;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum Cmds {
    Server(server::Server),
    Keygen(keygen::Keygen),
}

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmds,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.cmd {
        Cmds::Server(srv) => srv.run().await?,
        Cmds::Keygen(kg) => kg.run()?,
    }

    Ok(())
}
