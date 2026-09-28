//! Mobile-identity helper: reach the on-device daemon's gRPC through `adb
//! forward` and create/fetch an identity, returning the public key.
//!
//! Usage (device gRPC on 127.0.0.1:50051):
//!   adb forward tcp:50051 tcp:50051
//!   cargo run --release -p transferd --example mobile_identity -- create "Bob"
//!   cargo run --release -p transferd --example mobile_identity -- get

use std::str::FromStr;
use tonic::transport::Endpoint;
use transferd_api::{
    AccountServiceClient, CreateIdentityRequest, Empty,
};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "get".into());
    let url = std::env::var("TRANSFERD_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".into());
    let channel = Endpoint::from_str(&url).expect("valid endpoint").connect_lazy();
    let mut acct = AccountServiceClient::new(channel);
    match cmd.as_str() {
        "create" => {
            let name = args.next().unwrap_or_else(|| "Bob".into());
            match acct.create_identity(CreateIdentityRequest { display_name: name }).await {
                Ok(_) => println!("identity created"),
                Err(e) => {
                    eprintln!("create_identity failed: {e} (an identity may already exist)");
                }
            }
        }
        "get" => {
            match acct.get_public_key_hex(Empty {}).await {
                Ok(r) => println!("{}", r.into_inner().hex),
                Err(e) => {
                    eprintln!("get_public_key_hex failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command: {other} (use 'create <name>' or 'get')");
        }
    }
}