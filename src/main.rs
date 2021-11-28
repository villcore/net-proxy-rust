use tokio::io;
use std::future::Future;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, BufMut};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io::{Error, Cursor};
use rand::{RngCore, Rng, thread_rng};
use byte_order::{NumberWriter, ByteOrder};
use crypto::digest::Digest;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::mac::Mac;
use std::io::prelude::*;
use crypto::aessafe::AesSafe128Encryptor;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use cfb_mode::Cfb;
use aes::Aes128;
use std::fs::copy;

macro_rules! md5 {
    ($($x:expr),*) => {{
        let mut digest = crypto::md5::Md5::new();
        let mut result = [0; 16];
        $(digest.input($x);)*
        digest.result(&mut result);
        result
    }}
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = LocalConfig {
        pac_port: 50087,
        http_proxy_port: 50081,
    };
    println!("Start server pid: {}", std::process::id());
    let local_proxy = LocalProxy::new(config);
    local_proxy.run(tokio::signal::ctrl_c()).await;
    Ok(())
}

const HTTPS_CONNECT_RESP: &str = "HTTP/1.0 200 Connection Established\r\n\r\n";
const CONNECTION_BUF_SIZE: usize = 8 * 1024;

/// common build block
struct Connection {}

/// local side
// local proxy config
#[derive(Debug)]
struct LocalConfig {
    pac_port: u32,
    http_proxy_port: u32,
}

struct Config {
    uuid: &'static str,
    address: &'static str,
    port: u16,
    alert_id: u16,
    level: u16,
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
            _ = self.run_vmess_http_proxy(http_proxy_port) => {

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
                let mut tx_buffer = BytesMut::with_capacity(CONNECTION_BUF_SIZE);
                let size: usize = tcp_stream.read_buf(&mut tx_buffer).await.map_or(0usize, |t| t as usize);
                if size == 0 {
                    println!("Local socket {} closed ", local_address);
                    return;
                }

                // let s = String::from_utf8(Vec::from(&tx_buffer[..30])).unwrap();
                // println!("====== Read bytes {} form local socket {} =====", size, local_address);
                // println!("{}", s);
                // println!("===============================================");

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
                let mut dst_read_buffer = BytesMut::with_capacity(CONNECTION_BUF_SIZE);

                loop {
                    tokio::select! {
                    src_read_size = tcp_stream.read_buf(&mut tx_buffer) => {
                        let size = src_read_size.unwrap() as usize;
                        if size == 0 {
                           return;
                        }
                        println!("src read >>>>> {}", size);
                        dst_tcp_stream.write_buf(&mut tx_buffer).await;
                        println!("dst write >>>>> {}", size);
                        tx_buffer.clear();
                    }

                    dst_read_size = dst_tcp_stream.read_buf(&mut dst_read_buffer) => {
                        let size = dst_read_size.unwrap() as usize;
                        if size == 0 {
                            return;
                        }
                        println!("dst read <<<<< {}", size);
                        // LocalProxy::println(&dst_read_buffer[.. size]);
                        // let s = String::from_utf8(Vec::from(&dst_read_buffer[.. size])).unwrap();
                        tcp_stream.write_all(&dst_read_buffer[.. size]).await;
                        println!("src write <<<<< {}", size);
                        dst_read_buffer.clear();
                    }
                }
                }
            });
        }
    }

    pub async fn run_vmess_http_proxy(&self, port: u32) -> tokio::io::Result<()> {
        let tcp_listener = TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;
        loop {
            let (mut tcp_stream, local_address) = tcp_listener.accept().await?;
            println!("Accept new tcp stream form address {}", local_address);
            tokio::spawn(async move {
                let mut tx_buffer = BytesMut::with_capacity(CONNECTION_BUF_SIZE);
                let size: usize = tcp_stream.read_buf(&mut tx_buffer).await.map_or(0usize, |t| t as usize);
                if size == 0 {
                    println!("Local socket {} closed ", local_address);
                    return;
                }

                // let s = String::from_utf8(Vec::from(&tx_buffer[..30])).unwrap();
                // println!("====== Read bytes {} form local socket {} =====", size, local_address);
                // println!("{}", s);
                // println!("===============================================");

                let address_opt  = LocalProxy::parse_http_host(size, &tx_buffer[..size]);
                if address_opt.is_none() {
                    return;
                }

                let address = address_opt.unwrap();
                if 443 == address.port() {
                    tcp_stream.write_all(HTTPS_CONNECT_RESP.as_bytes()).await;
                    tcp_stream.flush().await;
                }

                let user = User {
                    uuid: "f3347094-0679-4e2d-822c-bbe25ec0abe3",
                    address: "c27s5.jamjams.net",
                    port: 23580,
                    alert_id: 8,
                    level: 0,
                    security: "auto",
                };
                let mut dst_tcp_stream = TcpStream::connect(format!("{}:{}", user.address, user.port)).await.unwrap();

                // mess handshake
                tx_buffer.clear();
                LocalProxy::mess_handshake(&mut tx_buffer, &address);
                println!("Write to {} , {} bytes", dst_tcp_stream.peer_addr().unwrap(), tx_buffer.len());
                dst_tcp_stream.write_all(&tx_buffer[..]).await.unwrap();
                println!("Write to {} , {} bytes finish", dst_tcp_stream.peer_addr().unwrap(), tx_buffer.len());
                let mut dst_read_buffer = BytesMut::with_capacity(CONNECTION_BUF_SIZE);
                println!("{} Start wait {} readable", LocalProxy::now_time_sec(), dst_tcp_stream.peer_addr().unwrap());
                // dst_tcp_stream.readable().await;
                // println!("{} End wait {} readable", LocalProxy::now_time_sec(), dst_tcp_stream.peer_addr().unwrap());
                let (mut rx, mut tx) = dst_tcp_stream.split();
                loop {
                    tokio::select! {
                    src_read_size = rx.read_buf(&mut dst_read_buffer) => {
                        let size = src_read_size.unwrap() as usize;
                        if size == 0 {
                           println!("{} End wait {} readable", LocalProxy::now_time_sec(), dst_tcp_stream.peer_addr().unwrap());
                           println!("Remote connection closed {}", dst_tcp_stream.peer_addr().unwrap());
                           return;
                        }
                        println!("src read >>>>> {}", size);
                        //dst_tcp_stream.write_buf(&mut tx_buffer).await;
                        println!("dst write >>>>> {:?}", &dst_read_buffer[..size]);
                        dst_read_buffer.clear();
                    }
                    }
                }

                // transfer data
                // if 80 == address.port() {
                //     dst_tcp_stream.write_all(&tx_buffer[..size]).await;
                //     tcp_stream.flush().await;
                //     println!("write {} bytes to http port", size);
                // }

                // tx_buffer.clear();
                // let mut dst_read_buffer = BytesMut::with_capacity(CONNECTION_BUF_SIZE);

                // loop {
                //     tokio::select! {
                //     src_read_size = tcp_stream.read_buf(&mut tx_buffer) => {
                //         let size = src_read_size.unwrap() as usize;
                //         if size == 0 {
                //            return;
                //         }
                //         println!("src read >>>>> {}", size);
                //         dst_tcp_stream.write_buf(&mut tx_buffer).await;
                //         println!("dst write >>>>> {}", size);
                //         tx_buffer.clear();
                //     }
                //
                //     dst_read_size = dst_tcp_stream.read_buf(&mut dst_read_buffer) => {
                //         let size = dst_read_size.unwrap() as usize;
                //         if size == 0 {
                //             return;
                //         }
                //         println!("dst read <<<<< {}", size);
                //         // LocalProxy::println(&dst_read_buffer[.. size]);
                //         // let s = String::from_utf8(Vec::from(&dst_read_buffer[.. size])).unwrap();
                //         tcp_stream.write_all(&dst_read_buffer[.. size]).await;
                //         println!("src write <<<<< {}", size);
                //         dst_read_buffer.clear();
                //     }
                // }
                // }
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

    fn mess_handshake(bytes_mut: &mut BytesMut, target_addr: &SocketAddr) -> io::Result<()> {
        let user = User {
            uuid: "f3347094-0679-4e2d-822c-bbe25ec0abe3",
            address: "c27s4.jamjams.net",
            port: 23580,
            alert_id: 8,
            level: 0,
            security: "auto",
        };

        let uuid_bytes = LocalProxy::decode_uuid(user.uuid).unwrap();
        println!("uuid_bytes = {:?}", uuid_bytes);

        let hash = LocalProxy::fnv1a("1111".as_bytes()).to_be_bytes();
        println!("1111 hash = {:?}", &hash[..]);

        bytes_mut.clear();

        // let encoded_auth_info =
        // let now = 1638105958;
        let mut now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // now = 1638105958;
        println!("{}", now);

        let mut ts = Vec::with_capacity(8);
        let mut le_writer = NumberWriter::with_order(ByteOrder::BE, ts);
        le_writer.write_u64(now).unwrap();
        let ts_slice_vec = le_writer.into_inner();
        let ts_slice = ts_slice_vec.as_slice();
        println!("t_unix_b {:?}", ts_slice);
        println!("uuid {:?}", uuid_bytes);

        // hmac
        let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), uuid_bytes.as_slice());
        hmac.input(ts_slice);

        // auth
        let mut auth = [0u8; 16];
        hmac.raw_result(&mut auth);
        bytes_mut.extend_from_slice(&auth);
        println!("auth = {:?}", auth);

        let pos = bytes_mut.len();
        // let encoded_req =
        let version = 1u8;
        bytes_mut.put_u8(version);

        let mut rand_bytes = [1u8; 33];
        let mut rng = thread_rng();
        // ///
        rng.fill_bytes(&mut rand_bytes);
        //
        let request_body_iv = &rand_bytes[0..16];
        let request_body_key = &rand_bytes[16..32];
        let req_resp_v = &rand_bytes[32];
        let resp_body_iv = md5!(request_body_iv);
        let resp_body_key = md5!(request_body_key);

        println!("{:?}\n {:?}\n {:?}\n {:?}\n {:?}\n", request_body_iv, request_body_key, req_resp_v, resp_body_iv, resp_body_key);
        bytes_mut.put(request_body_iv);
        bytes_mut.put(request_body_key);
        bytes_mut.put_u8(39);

        let opt = 1u8;
        bytes_mut.put_u8(opt);

        let security_str = "aes-128-gcm";
        let security = {
            match security_str {
                "aes-128-gcm" => {
                    3
                }

                "chacha20-poly1305" => {
                    4
                }

                "none" => {
                    5
                }

                "" => {
                    0
                }

                "auto" => {
                    1
                }

                _ => {
                    // Err("unknown security type ")
                    0
                }
            }
        };

        let mut padding_len = rng.gen_range(0..16) as u8;
        padding_len = 14;
        let padding_sec = padding_len << 4 | security;
        println!("padding_sec = {}", padding_sec);
        bytes_mut.put_u8(padding_sec);

        let reserved = 0u8;
        bytes_mut.put_u8(reserved);

        let cmd_tcp = 1u8;
        bytes_mut.put_u8(cmd_tcp);

        let port = target_addr.port();
        let mut port_vec: Vec<u8> = Vec::with_capacity(2);
        let mut le_writer = NumberWriter::with_order(ByteOrder::BE, port_vec);
        le_writer.write_u16(port).unwrap();
        let port_slice_inner = le_writer.into_inner();
        let port_slice = port_slice_inner.as_slice();
        bytes_mut.put(port_slice);

        let atype = {
            // TODO: 1 ip, 2 host
            2u8
        };
        bytes_mut.put_u8(atype);

        let mut host = target_addr.ip().to_string();
        host = "www.google.com".to_string();
        println!("target_host = {}", host);
        let address_as_bytes = host.as_bytes();
        let mut address_vec: Vec<u8> = Vec::with_capacity(address_as_bytes.len() + 1);
        address_vec.push(address_as_bytes.len() as u8);
        address_vec.extend_from_slice(address_as_bytes);
        bytes_mut.put(address_vec.as_slice());

        if padding_len > 0 {
            let mut padding_bytes: Vec<u8> = vec![0; padding_len as usize];
            ///
            rng.fill_bytes(padding_bytes.as_mut_slice());
            ///
            // padding_bytes.fill(0u8);
            bytes_mut.put(padding_bytes.as_slice());
        }

        // F
        // TODO:
        let mut f = LocalProxy::fnv1a(&bytes_mut[pos..]);
        /// f = 0;
        bytes_mut.put_u32(f);

        let header_key = md5!(uuid_bytes.as_slice(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let iv = md5!(ts_slice, ts_slice, ts_slice, ts_slice);

        println!("header_key = {:?}\n iv = {:?}", header_key, iv);

        let mut header_data = Vec::with_capacity(pos);
        header_data.extend_from_slice(&bytes_mut[..pos]);

        let mut request_data = Vec::with_capacity(bytes_mut[pos..].len());
        request_data.extend_from_slice(&bytes_mut[pos..]);

        println!("auth bytes = {:?}", &header_data);
        println!("final uncoded bytes = {:?}", &request_data);

        let mut cfb:Cfb<Aes128> = cfb_mode::Cfb::new_from_slices(&header_key, &iv).unwrap();
        cfb.encrypt(&mut request_data);
        println!("encrypt request bytes = {:?}", &request_data);

        //
        bytes_mut.clear();
        bytes_mut.extend_from_slice(&auth[..]);
        bytes_mut.extend_from_slice(request_data.as_slice());

        println!("final bytes = {:?}", &bytes_mut[..]);
        println!("auth = {:?}", auth);

        Ok(())
    }

    fn decode_uuid(uuid: &str) -> Option<Vec<u8>> {
        let uuid_replaced = str::replace(uuid, "-", "");
        if uuid_replaced.len() != 32 {
            None
        } else {
            let mut vec = Vec::with_capacity(16);
            for i in 0..16 {
                if let Ok(id) = u8::from_str_radix(&uuid_replaced[i*2..=i*2+1], 16) {
                    vec.push(id)
                }
            }

            if vec.len() == 16 {
                Some(vec)
            } else {
                None
            }
        }
    }

    fn fnv1a(x: &[u8]) -> u32 {
        let prime = 16777619;
        let mut hash = 0x811c9dc5;
        for byte in x.iter() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(prime);
        }
        hash
    }

    fn now_time_sec() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

pub struct User {
    uuid: &'static str,
    address: &'static str,
    port: u16,
    alert_id: u16,
    level: u16,
    security: &'static str,
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

#[cfg(test)]
pub mod test {
    use byte_order::{NumberWriter, ByteOrder};
    use crypto::mac::Mac;
    use crate::{User, LocalProxy};
    use rand::{thread_rng, Rng};
    use bytes::{BytesMut, BufMut};
    use cfb_mode::Cfb;
    use aes::Aes128;
    use cfb_mode::cipher::NewCipher;
    use aes::cipher::AsyncStreamCipher;

    #[test]
    pub fn test_auth_info() {
        let user = get_user();
        let uuid_bytes = LocalProxy::decode_uuid(user.uuid).unwrap();

        println!("test auth info");
        // auth_info

        let mut now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now = 1638025046;
        println!("{}", now);

        let mut ts = Vec::with_capacity(8);
        let mut le_writer = NumberWriter::with_order(ByteOrder::BE, ts);
        le_writer.write_u64(now).unwrap();
        let ts_slice_vec = le_writer.into_inner();
        let ts_slice = ts_slice_vec.as_slice();
        println!("t_unix_b {:?}", ts_slice);
        println!("uuid {:?}", uuid_bytes);

        // hmac
        let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), uuid_bytes.as_slice());
        hmac.input(ts_slice);

        // auth
        let mut auth = [0u8; 16];
        hmac.raw_result(&mut auth);
        println!("auth = {:?}", auth);
        assert_eq!(auth, [185,190, 208, 159, 33, 246, 234, 253, 20, 78, 186, 214, 92, 46, 149, 183]);

        // request


        // cfg encode
    }

    pub fn get_user() -> User {
        User {
            uuid: "f3347094-0679-4e2d-822c-bbe25ec0abe3",
            address: "c27s4.jamjams.net",
            port: 23580,
            alert_id: 8,
            level: 0,
            security: "auto",
        }
    }
}