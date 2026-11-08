//! Live TLS/network fixtures are deliberately confined to a test-only module.
//! The transport policy is the same production builder; only synthetic DNS
//! and a generated, process-local trust root are supplied by the fixture.
//! No test certificates, keys, or other credentials are committed to Git.

use super::webhook_client_builder;
use std::{
    fs,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const HOSTNAME: &str = "fixture.invalid";
const PROXY_CHILD_ENV: &str = "EVGL_WEBHOOK_ISOLATED_PROXY_CHILD";

struct TlsFixture {
    address: SocketAddr,
    directory: PathBuf,
    certificate: reqwest::Certificate,
    server: Child,
}

impl TlsFixture {
    fn launch(response: Option<&'static [u8]>) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after UNIX epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "evgl-webhook-tls-fixture-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir(&directory).expect("create private test certificate directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("restrict ephemeral private key directory permissions");
        }
        let key = directory.join("key.pem");
        let cert = directory.join("cert.pem");
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=fixture.invalid",
                "-addext",
                "subjectAltName=DNS:fixture.invalid",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("OpenSSL CLI is required by the Linux transport fixture");
        assert!(generated.success(), "OpenSSL failed to generate a synthetic test certificate");
        let certificate = reqwest::Certificate::from_pem(
            &fs::read(&cert).expect("read ephemeral test certificate"),
        )
        .expect("generated PEM is valid");

        // Bind port zero to obtain a free loopback port. Only the generated
        // fixture listens there; the real production egress validator would
        // still reject loopback and cannot be bypassed by this test helper.
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("reserve an ephemeral loopback port");
        let address = listener.local_addr().expect("get ephemeral port");
        drop(listener);

        let mut command = Command::new("openssl");
        command
            .arg("s_server")
            .arg("-accept")
            .arg(format!("127.0.0.1:{}", address.port()))
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if response.is_some() {
            command.arg("-quiet").stdin(Stdio::piped());
        } else {
            command.arg("-www").stdin(Stdio::null());
        }
        let mut server = command.spawn().expect("launch local OpenSSL TLS responder");
        if response.is_some() {
            // This is a one-shot custom response on the OpenSSL stdin pipe.
            // A TCP readiness probe can consume that response before the
            // actual HTTP client connects. Wait for server startup instead.
            thread::sleep(Duration::from_millis(350));
            assert!(
                server.try_wait().expect("check custom TLS fixture").is_none(),
                "custom TLS fixture exited before accepting a connection"
            );
        } else {
            let mut ready = false;
            for _ in 0..100 {
                if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                    ready = true;
                    break;
                }
                assert!(
                    server.try_wait().expect("check TLS fixture process").is_none(),
                    "TLS fixture exited early"
                );
                thread::sleep(Duration::from_millis(20));
            }
            assert!(ready, "local TLS fixture did not bind within two seconds");
        }
        if let Some(wire) = response {
            server
                .stdin
                .as_mut()
                .expect("custom-response server accepts fixture input")
                .write_all(wire)
                .expect("write synthetic HTTP redirect");
        }
        Self {
            address,
            directory,
            certificate,
            server,
        }
    }

    fn url(&self, hostname: &str) -> String {
        format!("https://{hostname}:{}/", self.address.port())
    }

    fn client(&self, hostname: &str, trust_fixture: bool) -> reqwest::Client {
        let mut builder = webhook_client_builder().resolve(hostname, self.address);
        if trust_fixture {
            builder = builder.add_root_certificate(self.certificate.clone());
        }
        builder.build().expect("build test client with real egress transport policy")
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn trusted_tls_hostname_and_pinned_dns_reach_the_fixture() {
    let fixture = TlsFixture::launch(None);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio test runtime");
    runtime.block_on(async {
        // fixture.invalid does not require real DNS. The client is pinned to
        // the fixture, but TLS still validates the original hostname/SNI.
        let response = fixture
            .client(HOSTNAME, true)
            .get(fixture.url(HOSTNAME))
            .send()
            .await
            .expect("trusted synthetic TLS endpoint must be reachable");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    });
}

#[test]
fn unknown_ca_and_wrong_tls_hostname_are_rejected() {
    let fixture = TlsFixture::launch(None);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio test runtime");
    runtime.block_on(async {
        let no_trust = fixture
            .client(HOSTNAME, false)
            .get(fixture.url(HOSTNAME))
            .send()
            .await;
        assert!(no_trust.is_err(), "untrusted test server certificate must be rejected");

        let wrong_hostname = "not-fixture.invalid";
        let mismatched = fixture
            .client(wrong_hostname, true)
            .get(fixture.url(wrong_hostname))
            .send()
            .await;
        assert!(mismatched.is_err(), "a trusted certificate for the wrong hostname must fail");

        let non_tls = fixture
            .client(HOSTNAME, true)
            .get(format!("http://{HOSTNAME}:{}/", fixture.address.port()))
            .send()
            .await;
        assert!(non_tls.is_err(), "HTTP downgrade must be rejected");
    });
}

#[test]
fn https_redirect_to_private_endpoint_is_not_followed() {
    let wire = b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:9/admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let fixture = TlsFixture::launch(Some(wire));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio test runtime");
    runtime.block_on(async {
        let response = fixture
            .client(HOSTNAME, true)
            .get(fixture.url(HOSTNAME))
            .send()
            .await
            .expect("a redirected response should be returned without following it");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(
            response.headers().get(reqwest::header::LOCATION).unwrap(),
            "https://127.0.0.1:9/admin"
        );
    });
}

#[test]
fn proxy_environment_cannot_override_the_pinned_tls_destination() {
    if std::env::var_os(PROXY_CHILD_ENV).is_some() {
        let fixture = TlsFixture::launch(None);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio test runtime");
        runtime.block_on(async {
            let response = fixture
                .client(HOSTNAME, true)
                .get(fixture.url(HOSTNAME))
                .send()
                .await
                .expect("HTTPS_PROXY and ALL_PROXY must not intercept a vetted direct request");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
        });
        return;
    }

    // Run proxy-environment mutations only in a separate process. Rust tests
    // execute concurrently; mutating process-wide env in the normal test
    // runner would otherwise make concurrent tests nondeterministic.
    let test_binary = std::env::current_exe().expect("resolve current Rust test binary");
    let output = Command::new(test_binary)
        .arg("--exact")
        .arg("generic_webhook::transport_integration_tests::proxy_environment_cannot_override_the_pinned_tls_destination")
        .arg("--nocapture")
        .env(PROXY_CHILD_ENV, "1")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("all_proxy", "http://127.0.0.1:9")
        .output()
        .expect("spawn isolated proxy environment test process");
    assert!(
        output.status.success(),
        "proxy isolation child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
