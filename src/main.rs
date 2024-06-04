mod no_cid;

use anyhow::{anyhow, Context};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::RootCertStore;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::net::{Ipv4Addr, SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Instant};
use crate::no_cid::NoConnectionIdGenerator;

pub const SERVER_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
pub const CLIENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

fn main() -> anyhow::Result<()> {
    std::env::set_var("SSLKEYLOGFILE", "keylog.key");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to initialize tokio");

    let result = rt.block_on(run());

    result
}

async fn run() -> anyhow::Result<()> {
    // Certificates
    let server_name = "server-name";
    let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Let a server listen in the background
    let server = server_endpoint(cert.clone(), key.into())?;
    let server_task = tokio::spawn(server_listen(server));

    // Make repeated requests
    let client = client_endpoint(cert)?;
    let start = Instant::now();
    println!("0.00s CONNECT");
    let connection = client.connect(SERVER_ADDR, server_name)?.await?;

    let request = "GET /index.html";
    for _ in 0..10 {
        println!("{:.02}s {request}", start.elapsed().as_secs_f64());

        let (mut tx, mut rx) = connection.open_bi().await?;
        tx.write_all(request.as_bytes()).await?;
        tx.finish()?;

        rx.read_to_end(usize::MAX).await?;
    }

    println!(
        "Done in {:.2}s! Waiting for connection close...",
        start.elapsed().as_secs_f64()
    );

    connection.close(VarInt::from_u32(0), &[]);

    drop(connection);
    drop(client);

    server_task
        .await
        .context("server task crashed")?
        .context("server task errored")?;

    println!(
        "Time from start to connection closed: {:.02}s",
        start.elapsed().as_secs_f64()
    );

    Ok(())
}

async fn server_listen(endpoint: Endpoint) -> anyhow::Result<()> {
    let conn = endpoint
        .accept()
        .await
        .ok_or(anyhow!("failed to accept incoming connection"))?
        .await?;

    let response = "<html>
      <h1>Hello there</h1>
    </html>";

    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        // Read the request
        let request = rx.read_to_end(usize::MAX).await?;
        assert_eq!(request, b"GET /index.html");

        // Respond
        tx.write(response.as_bytes()).await?;
        tx.finish()?;
    }

    Ok(())
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(SERVER_ADDR)?;
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config());
    Endpoint::new(
        endpoint_config(),
        Some(server_config),
        socket,
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
) -> anyhow::Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(CLIENT_ADDR)?;
    let mut endpoint = Endpoint::new(
        endpoint_config(),
        None,
        socket,
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create client endpoint")?;

    endpoint.set_default_client_config(client_config(server_cert)?);

    Ok(endpoint)
}

fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.cid_generator(|| Box::new(NoConnectionIdGenerator));
    config
}

fn client_config(server_cert: CertificateDer<'_>) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(server_cert)?;

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
        ..default_provider
    };

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(transport_config()));

    Ok(client_config)
}

fn transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.mtu_discovery_config(None);
    config
}
