//! The local proxies: SOCKS5 and HTTP-CONNECT.
//!
//! With these running, *any* application can reach a paired node's services by name, with no
//! per-service setup and no knowledge of the overlay:
//!
//! ```text
//! curl --socks5-hostname 127.0.0.1:PORT https://ssh.<node>.td:22/
//! curl -x http://127.0.0.1:PORT http://web.<node>.td:8080/
//! ```
//!
//! Only `CONNECT` is proxied, which is what an encrypted stream needs; there is no plain-HTTP
//! path that could be used to smuggle a request somewhere the ACL forbids. The target is always
//! resolved *through* the overlay, so a name that is not a paired service simply fails.

use std::io::ErrorKind;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{OverlayError, Result};
use crate::node::OverlayNode;

/// SOCKS5: no authentication, `CONNECT` only, domain names of the form
/// `<service>.<node>.td`.
pub async fn serve_socks(node: OverlayNode) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| OverlayError::Listen {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            source: e,
        })?;
    let local = listener.local_addr().map_err(OverlayError::Io)?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let node = node.clone();
            tokio::spawn(async move {
                let _ = socks5_session(socket, node).await;
            });
        }
    });
    Ok(local)
}

/// HTTP: `CONNECT host:port`, for the many tools that take an HTTP proxy.
pub async fn serve_http(node: OverlayNode) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| OverlayError::Listen {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            source: e,
        })?;
    let local = listener.local_addr().map_err(OverlayError::Io)?;
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let node = node.clone();
            tokio::spawn(async move {
                let _ = http_session(socket, node).await;
            });
        }
    });
    Ok(local)
}

async fn socks5_session(mut socket: TcpStream, node: OverlayNode) -> Result<()> {
    // Greeting: version 5, one method, "no authentication".
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(OverlayError::protocol("not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        socket.write_all(&[5, 0xff]).await?;
        return Err(OverlayError::protocol("this proxy needs no authentication"));
    }
    socket.write_all(&[5, 0]).await?;

    // Request: CONNECT (0x01) + domain name + port.
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).await?;
    if request[0] != 5 || request[1] != 1 {
        socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(OverlayError::protocol("only CONNECT is proxied"));
    }
    // Only a domain name (ATYP 3) can name an overlay service; an IP address cannot.
    if request[3] != 3 {
        socket.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(OverlayError::protocol(
            "only <service>.<node>.td names are proxied",
        ));
    }
    let mut len = [0u8; 1];
    socket.read_exact(&mut len).await?;
    let mut host = vec![0u8; len[0] as usize];
    socket.read_exact(&mut host).await?;
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    // The port the client asked for is informational: the overlay endpoint has its own.
    let host = String::from_utf8_lossy(&host).to_string();

    match open(&node, &host).await {
        Ok(local) => {
            // A bound zero port is what the overlay replies on; tell the client it may proceed.
            socket
                .write_all(&[
                    5,
                    0,
                    0,
                    1,
                    127,
                    0,
                    0,
                    1,
                    local.port().to_be_bytes()[0],
                    local.port().to_be_bytes()[1],
                ])
                .await?;
            splice(socket, local).await;
            Ok(())
        }
        Err(_) => {
            socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Err(OverlayError::protocol(format!(
                "{host} is not reachable through the overlay"
            )))
        }
    }
}

async fn http_session(mut socket: TcpStream, node: OverlayNode) -> Result<()> {
    let mut head = vec![0u8; 0];
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let Ok(n) = socket.read(&mut byte).await else {
            break;
        };
        if n == 0 {
            break;
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let mut parts = text.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method != "CONNECT" {
        socket
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await?;
        return Err(OverlayError::protocol("only CONNECT is proxied"));
    }
    // The authority is `<service>.<node>.td:<port>`; the port is informational.
    let host = target
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&target)
        .to_string();
    match open(&node, &host).await {
        Ok(local) => {
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            splice(socket, local).await;
            Ok(())
        }
        Err(_) => {
            socket
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await?;
            Err(OverlayError::protocol(format!(
                "{host} is not reachable through the overlay"
            )))
        }
    }
}

/// Split a proxied host into `(service, node)`: `<service>.<node>.td`.
pub fn parse_host(host: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let rest = host.strip_suffix(".td")?;
    let (service, node) = rest.split_once('.')?;
    if service.is_empty() || node.is_empty() {
        return None;
    }
    Some((service.to_string(), node.to_string()))
}

/// Open a local endpoint for `<service>.<node>.td` through the overlay.
///
/// A host whose second label is a full node id addresses that node; anything else is treated as
/// a service group, so `<service>.<group>.td` reaches one member of a group.
async fn open(node: &OverlayNode, host: &str) -> Result<SocketAddr> {
    let Some((service, node_id)) = parse_host(host) else {
        return Err(OverlayError::protocol(format!(
            "{host} is not a <service>.<node>.td name"
        )));
    };
    let (local, _route) = node.connect(&node_id, &service).await?;
    Ok(local)
}

/// Copy bytes both ways between the client and the overlay endpoint, until either side stops.
///
/// If the overlay side fails (the session was lost), the client's connection is reset rather than closed: a clean
/// close would tell the application that a stream cut short was complete.
pub async fn splice(client: TcpStream, local: SocketAddr) {
    let Ok(server) = TcpStream::connect(local).await else {
        return;
    };
    let (client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let mut buf = vec![0u8; 32 * 1024];
    // The upload hands back the client's read half when it is stopped, so the halves can be rejoined to reset.
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let upload = tokio::spawn(async move {
        let mut client_read = client_read;
        let mut up_buf = vec![0u8; 32 * 1024];
        loop {
            tokio::select! {
                Ok(()) = &mut stop_rx => break,
                read = client_read.read(&mut up_buf) => match read {
                    Ok(n) if n > 0 => {
                        if server_write.write_all(&up_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
            }
        }
        client_read
    });
    let mut failed = false;
    loop {
        match server_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if client_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    if failed {
        let _ = stop_tx.send(());
        if let Ok(client_read) = upload.await {
            reset(client_read.unsplit(client_write));
        }
        return;
    }
    let _ = client_write.shutdown().await;
    upload.abort();
}

/// Close a TCP connection with a reset instead of a FIN, so the reader at the other end gets an error and not the
/// end of the stream.
pub fn reset(socket: TcpStream) {
    #[allow(deprecated)]
    let _ = socket.set_linger(Some(std::time::Duration::ZERO));
    drop(socket);
}

/// A refusal the caller can turn into the right protocol error.
pub fn refused() -> std::io::Error {
    std::io::Error::new(
        ErrorKind::PermissionDenied,
        "not reachable through the overlay",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session lost under a local connection resets the application's socket: it reads an error, not the end.
    #[tokio::test]
    async fn a_failed_overlay_side_resets_the_client() {
        let front = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let front_addr = front.local_addr().expect("address");
        let service = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let service_addr = service.local_addr().expect("address");
        // The overlay end accepts, then goes away with a reset.
        tokio::spawn(async move {
            let (socket, _) = service.accept().await.expect("accept");
            reset(socket);
        });
        let client = tokio::spawn(async move {
            TcpStream::connect(front_addr).await.expect("connect")
        });
        let (accepted, _) = front.accept().await.expect("accept");
        let mut app = client.await.expect("join");
        tokio::spawn(splice(accepted, service_addr));
        let mut buf = [0u8; 16];
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), app.read(&mut buf))
            .await
            .expect("the reset arrives");
        assert!(outcome.is_err(), "a reset, not the end of the stream: {outcome:?}");
    }

    #[test]
    fn an_overlay_host_splits_into_a_service_and_a_node() {
        assert_eq!(
            parse_host("ssh.aa1122334455667788990011223344556677889900112233445566778899.td"),
            Some((
                "ssh".to_string(),
                "aa1122334455667788990011223344556677889900112233445566778899".to_string()
            ))
        );
        assert_eq!(parse_host("web.bb.td"), Some(("web".into(), "bb".into())));
    }

    #[test]
    fn anything_that_is_not_an_overlay_name_is_refused() {
        for bad in [
            "example.com",
            "1.2.3.4",
            "ssh.aa.td.extra",
            ".td",
            "ssh..td",
            "",
        ] {
            assert_eq!(parse_host(bad), None, "{bad:?} is not an overlay name");
        }
        // The port is not part of the name.
        assert!(parse_host("ssh.aa.td:22").is_none());
    }
}
