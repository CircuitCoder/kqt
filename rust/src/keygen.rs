mod cert;

use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use x509_cert::der::{EncodePem, pem::LineEnding};

use crate::cert::ParsedPrivateKey;

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Pem,
    String,
}

#[derive(Subcommand)]
enum Cmds {
    Private,
    Public {
        /// Private key
        privkey: String,
    },
    Node {
        /// Private key of the issuer
        issuer: String,

        /// Suffix of the CN
        #[arg(short, long)]
        suffix: String,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::String)]
        format: OutputFormat,
    } 
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
        Cmds::Private => {
            let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let buf = ed25519_dalek::SECRET_KEY_LENGTH / 2 * 3 + 1; // Base64 encoded length
            let mut encoded = String::with_capacity(buf);
            base64::engine::general_purpose::STANDARD.encode_string(key.to_bytes(), &mut encoded);
            println!("k.{}", encoded);
        }
        Cmds::Public { privkey } => {
            let ParsedPrivateKey(sk) = ParsedPrivateKey::try_from(privkey.as_str())?;
            let pk = ed25519_dalek::VerifyingKey::from(&sk);
            let buf = ed25519_dalek::PUBLIC_KEY_LENGTH / 2 * 3 + 1;
            let mut encoded = String::with_capacity(buf);
            base64::engine::general_purpose::STANDARD.encode_string(pk.to_bytes(), &mut encoded);
            println!("t.{}", encoded);
        }
        Cmds::Node { issuer, format, suffix } => {
            let ParsedPrivateKey(issuer_sk) = ParsedPrivateKey::try_from(issuer.as_str())?;
            let issuer_pk = ed25519_dalek::VerifyingKey::from(&issuer_sk);

            // Generate key
            let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

            // Generate TBS cert
            let tbs = cert::recover_tbs_cert(sk.clone(), issuer_pk, &suffix)?;
            let sig = cert::sign_cert(&tbs, &issuer_sk)?;

            match format {
                OutputFormat::Pem => {
                    let cert = cert::recover_cert(sk, issuer_pk, sig, &suffix)?;
                    // TODO: check signature again
                    println!("{}", cert.to_pem(LineEnding::LF)?);
                }
                OutputFormat::String => {
                    let sk_buflen = ed25519_dalek::SECRET_KEY_LENGTH / 2 * 3 + 1;
                    let sig_bytes = sig.to_bytes();
                    let sig_buflen = sig_bytes.len() / 2 * 3 + 1;
                    let mut sk_encoded = String::with_capacity(sk_buflen);
                    let mut sig_encoded = String::with_capacity(sig_buflen);
                    base64::engine::general_purpose::STANDARD.encode_string(sk.to_bytes(), &mut sk_encoded);
                    base64::engine::general_purpose::STANDARD.encode_string(sig_bytes, &mut sig_encoded);
                    println!("c.{}.{}", sk_encoded, sig_encoded);
                }
            }
        }
    }

    Ok(())
}
