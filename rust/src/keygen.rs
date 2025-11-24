mod cert;

use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use x509_cert::der::{EncodePem, pem::LineEnding};

use crate::cert::ParsedKeypair;

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Pem,
    String,
}

#[derive(Subcommand)]
enum Cmds {
    Private {
        /// Private key of the issuer
        issuer: Option<String>,

        /// Suffix of the CN
        #[arg(short, long)]
        suffix: String,
    },
    /// Convert a private key to the corresponding public key. The private key is given in stdin.
    Public {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::String)]
        format: OutputFormat,

        /// Suffix of the CN
        #[arg(short, long)]
        suffix: String,
    },
}

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmds,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmds::Public { format, suffix } => {
            let kp_str = std::io::read_to_string(std::io::stdin())?;
            let kp = ParsedKeypair::try_from(kp_str.trim())?;

            match format {
                OutputFormat::Pem => {
                    let cert = kp.try_to_cert(&suffix)?;
                    println!("{}", cert.to_pem(LineEnding::LF)?);
                }
                OutputFormat::String => {
                    let pk = ed25519_dalek::VerifyingKey::from(&kp.sk);
                    let buf = ed25519_dalek::PUBLIC_KEY_LENGTH / 2 * 3 + 1;
                    let mut encoded = String::with_capacity(buf);
                    base64::engine::general_purpose::STANDARD
                        .encode_string(pk.to_bytes(), &mut encoded);
                    println!("p.{}", encoded);
                }
            }
        }
        Cmds::Private { issuer, suffix } => {
            // Generate key
            let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let pk: ed25519_dalek::VerifyingKey = sk.verifying_key();

            let issuer_sk = if let Some(i) = issuer {
                ParsedKeypair::try_from(i.as_str())?.sk
            } else {
                sk.clone()
            };
            let issuer_pk = issuer_sk.verifying_key();

            // Generate TBS cert
            let tbs = cert::recover_tbs_cert(pk, issuer_pk, &suffix)?;
            let sig = cert::sign_cert(&tbs, &issuer_sk)?;

            let key_buflen = ed25519_dalek::SECRET_KEY_LENGTH / 2 * 3 + 1;
            let sig_bytes = sig.to_bytes();
            let sig_buflen = sig_bytes.len() / 2 * 3 + 1;

            let mut sk_encoded = String::with_capacity(key_buflen);
            base64::engine::general_purpose::STANDARD.encode_string(sk.to_bytes(), &mut sk_encoded);
            if issuer_sk == sk {
                // Self-signed
                println!("s.{}", sk_encoded);
            } else {
                let mut issuer_encoded = String::with_capacity(key_buflen);
                let mut sig_encoded = String::with_capacity(sig_buflen);
                base64::engine::general_purpose::STANDARD
                    .encode_string(issuer_pk.to_bytes(), &mut issuer_encoded);
                base64::engine::general_purpose::STANDARD
                    .encode_string(sig_bytes, &mut sig_encoded);
                println!("s.{}.{}.{}", sk_encoded, issuer_encoded, sig_encoded);
            }
        }
    }

    Ok(())
}
