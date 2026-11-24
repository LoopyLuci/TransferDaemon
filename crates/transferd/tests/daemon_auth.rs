//! gRPC authN tests: daemons with an `auth_token` reject unauthenticated calls
//! and accept bearer-authenticated calls; daemons without a token stay open.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

use transferd_api::auth::AuthChannel;
use transferd_api::{AccountServiceClient, CreateIdentityRequest, Empty};
use transferd_lib::state::DaemonState;
use transferd_lib::{grpc::add_all_services, new_state};

async fn start_daemon(state: Arc<Mutex<DaemonState>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        add_all_services(Server::builder(), state)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://{addr}")
}

#[tokio::test]
async fn unauthenticated_request_rejected_when_token_set() {
    let state = new_state();
    {
        let mut s = state.lock();
        s.auth_token = Some("test-token-abcdef123456".into());
    }
    let url = start_daemon(state).await;

    // Plain channel (no auth header) → UNAUTHENTICATED.
    let channel = Channel::from_shared(url).unwrap().connect().await.unwrap();
    let mut client = AccountServiceClient::new(channel);
    let err = client
        .create_identity(CreateIdentityRequest { display_name: "Eve".into() })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "no token must be rejected");
}

#[tokio::test]
async fn wrong_token_rejected() {
    let state = new_state();
    {
        let mut s = state.lock();
        s.auth_token = Some("correct-token".into());
    }
    let url = start_daemon(state).await;

    let channel = Channel::from_shared(url).unwrap().connect().await.unwrap();
    let mut client = AccountServiceClient::new(AuthChannel::new(channel, "wrong-token"));
    let err = client.create_identity(CreateIdentityRequest { display_name: "Eve".into() })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "wrong token must be rejected");
}

#[tokio::test]
async fn authenticated_request_succeeds_when_token_set() {
    let state = new_state();
    {
        let mut s = state.lock();
        s.auth_token = Some("valid-token-42".into());
    }
    let url = start_daemon(state).await;

    let channel = Channel::from_shared(url).unwrap().connect().await.unwrap();
    let mut client = AccountServiceClient::new(AuthChannel::new(channel, "valid-token-42"));
    let reply = client
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.phrase.split_whitespace().count(), 12);
}

#[tokio::test]
async fn no_token_daemon_accepts_plain_requests() {
    let state = new_state(); // auth_token stays None
    let url = start_daemon(state).await;

    let channel = Channel::from_shared(url).unwrap().connect().await.unwrap();
    let mut client = AccountServiceClient::new(channel);
    let reply = client
        .create_identity(CreateIdentityRequest { display_name: "Dev".into() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.phrase.split_whitespace().count(), 12);

    // The identity RPC also succeeds over the same open channel.
    let id = client.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(id.has_identity);
}
