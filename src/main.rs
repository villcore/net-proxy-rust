use tokio::io;
use tokio::signal::unix::signal;
use std::future::Future;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::BytesMut;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io::Error;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = LocalConfig {
        pac_port: 50087,
        http_proxy_port: 50082,
    };

    println!("Start server pid: {}", std::process::id());
    let local_proxy = LocalProxy::new(config);
    local_proxy.run(tokio::signal::ctrl_c()).await;
    Ok(())
}

const HTTPS_CONNECT_RESP: &str = "HTTP/1.0 200 Connection Established\r\n\r\n";

/// common build block
struct Connection {}

/// local side
// local proxy config
#[derive(Debug)]
struct LocalConfig {
    pac_port: u32,
    http_proxy_port: u32,
    // remote server list, use enum
}

struct LocalProxy {
    config: LocalConfig,
}

impl LocalProxy {
    pub fn new(config: LocalConfig) -> Self {
        Self {
            config
        }
    }

    pub async fn run(&self, shutdown: impl Future) -> tokio::io::Result<()> {
        let LocalConfig { pac_port, http_proxy_port, .. } = self.config;
        println!("LocalProxy run, pac_port: {}, http_proxy_port: {}", pac_port, http_proxy_port);

        // start pac http server

        // start http proxy server
        tokio::select! {
            _ = self.run_http_proxy(http_proxy_port) => {

            },

            _ = shutdown => {
                println!("Shutdown")
            }
        }
        Ok(())
    }

    pub async fn run_http_proxy(&self, port: u32) -> tokio::io::Result<()> {
        let tcp_listener = TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;
        loop {
            let (mut tcp_stream, local_address) = tcp_listener.accept().await?;
            println!("Accept new tcp stream form address {}", local_address);
            tokio::spawn(async move {
                let mut tx_buffer = BytesMut::with_capacity(4 * 1024);
                let size: usize = tcp_stream.read_buf(&mut tx_buffer).await.map_or(0usize, |t| t as usize);
                if size == 0 {
                    println!("Local socket {} closed ", local_address);
                    return;
                }

                let s = String::from_utf8(Vec::from(&tx_buffer[..30])).unwrap();
                println!("====== Read bytes {} form local socket {} =====", size, local_address);
                println!("{}", s);
                println!("===============================================");

                let mut dst_tcp_stream_opt = None;
                match LocalProxy::parse_http_host(size, &tx_buffer[..size]) {
                    Some(address) => {
                        if 443 == address.port() {
                            tcp_stream.write_all(HTTPS_CONNECT_RESP.as_bytes()).await;
                            tcp_stream.flush().await;
                        }

                        let mut dst_tcp_stream = TcpStream::connect(address).await.unwrap();
                        if 80 == address.port() {
                            dst_tcp_stream.write_all(&tx_buffer[..size]).await;
                            tcp_stream.flush().await;
                            println!("write {} bytes to http port", size);
                        }
                        dst_tcp_stream_opt = Some(dst_tcp_stream);
                    }
                    _ => {
                        println!("Parse address error");
                        return;
                    }
                }

                tx_buffer.clear();
                let mut dst_tcp_stream = dst_tcp_stream_opt.unwrap();
                let(mut src_rx, mut src_tx) = tcp_stream.split();
                let (mut dst_rx, mut dst_tx) = dst_tcp_stream.split();
                let mut dst_read_buffer = BytesMut::with_capacity(4 * 1024);

                loop {
                    tokio::select! {
                    src_read_size = src_rx.read_buf(&mut tx_buffer) => {
                        let size = src_read_size.unwrap() as usize;
                        if size == 0 {
                           return;
                        }
                        println!("src read >>>>> {}", size);
                        dst_tx.write_buf(&mut tx_buffer).await;
                        dst_tx.flush().await;
                        println!("dst write >>>>> {}", size);
                        tx_buffer.clear();
                    }

                    dst_read_size = dst_rx.read_buf(&mut dst_read_buffer) => {
                        let size = dst_read_size.unwrap() as usize;
                        if size == 0 {
                            return;
                        }
                        println!("dst read <<<<< {}", size);
                        // LocalProxy::println(&dst_read_buffer[.. size]);
                        // let s = String::from_utf8(Vec::from(&dst_read_buffer[.. size])).unwrap();
                        src_tx.write_all(&dst_read_buffer[.. size]).await;
                        src_tx.flush().await;
                        println!("src write <<<<< {}", size);
                        dst_read_buffer.clear();
                    }
                }
                }
            });
        }
    }

    fn parse_http_host(size: usize, bytes: &[u8]) -> Option<SocketAddr> {
        let mut i = 0;
        while i < size - 6 {
            if b"Host: " == &bytes[i..i + 6] {
                let mut only_http = true;
                for j in (i + 6)..size {
                    if b':' == bytes[j] {
                        only_http = false;
                    }

                    if b"\r\n" == &bytes[j..j + 2] {
                        let s = &bytes[i + 6..j];
                        let host = String::from_utf8(Vec::from(s)).unwrap();
                        let address = if only_http {
                            format!("{}:80", host)
                        } else {
                            host
                        };
                        println!("------------------------------{}", address);
                        let mut addrs_iter = address.to_socket_addrs().unwrap();
                        return addrs_iter.next();
                    }
                }
            }
            i = i + 1;
        }
        None
    }

    fn println(bytes: &[u8]) {
        let s = String::from_utf8(Vec::from(bytes)).unwrap();
        println!("===============================================");
        println!("{}", s);
        println!("===============================================");
    }
}


/// remote side
// remote server config
struct RemoteConfig {}

struct RemoteServer {}

impl RemoteServer {
    pub fn new(config: LocalConfig) -> Self {
        todo!()
    }

    pub fn run() {}
}