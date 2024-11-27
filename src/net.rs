pub mod proto;

use std::clone::Clone;
use std::error::Error;
use std::fmt::Display;
use std::marker::Copy;

#[derive(Debug, Copy, Clone)]
pub enum NetworkErrorCode {

    // general
    Unknown,
    IllegalArgument,
    CryptoErrorOccurred,

    // specific
    UnsupportedAlgorithm,
    UnsupportedCipherSuite,
    UnsupportedFragmentType,
    UnsupportedVersion,
    BufferLengthIncorrect,
    BufferTooShort,
    IllegalCipherSuite,
    VerificationFailed,

}

#[derive(Debug)]
pub struct NetworkError {
    err_code: NetworkErrorCode
}

impl NetworkError {

    pub fn new(err_code: NetworkErrorCode) -> Self {
        return Self{
            err_code: err_code,
        };
    }

    pub fn err_code(&self) -> NetworkErrorCode {
        return self.err_code;
    }

}

impl Display for NetworkError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "NetworkError: {}", match &self.err_code {
            NetworkErrorCode::Unknown                 => "unknown",
            NetworkErrorCode::IllegalArgument         => "illegal argument",
            NetworkErrorCode::CryptoErrorOccurred     => "crypto error occurred",
            NetworkErrorCode::UnsupportedAlgorithm    => "unsupported algorithm",
            NetworkErrorCode::UnsupportedCipherSuite  => "unsupported cipher suite",
            NetworkErrorCode::UnsupportedFragmentType => "unsupported fragment type",
            NetworkErrorCode::UnsupportedVersion      => "unsupported version",
            NetworkErrorCode::BufferLengthIncorrect   => "buffer length incorrect",
            NetworkErrorCode::BufferTooShort          => "buffer too short",
            NetworkErrorCode::IllegalCipherSuite      => "illegal cipher suite",
            NetworkErrorCode::VerificationFailed      => "verification failed"
        });
    }

}

impl Error for NetworkError {}

// use std::net::SocketAddr;
// use std::net::UdpSocket;
// use std::collections::HashMap;
// use quiche::Config;
// use quiche::Connection;
// use quiche::ConnectionId;
// use quiche::RecvInfo;
// use quiche::accept;
//
// // https://docs.quic.tech/quiche/
//
// pub fn serve() {
//
//     let sock: UdpSocket = UdpSocket::bind("127.0.0.1:65535").unwrap();
//     let local_addr: SocketAddr = sock.local_addr().unwrap();
//
//     let conf: Config = Config::new(0x00000001).unwrap();
//     conf.verify_peer(false); // 将来的にtrueにしたい（Client Auth）
//     conf.grease(false);
//
//     let conn_ids: HashMap<ConnectionId, Connection> = HashMap::<ConnectionId, Connection>::new();
//     let conn: Connection = accept(&scid, None, local_addr, peer, &mut conf).unwrap();
//     // accept はどこなんだ...？ peer addrどうやって持ってこればいいのかわからん。
//
//     let mut buf: [u8; 65536] = [0; 65536];
//     loop {
//
//         let (r, from_addr): (usize, SocketAddr) = sock.recv_from(&mut buf[..]).unwrap();
//         let r = match conn.recv(&mut buf[..r], RecvInfo{ from: from_addr, to: local_addr }) {
//             Ok(v)  => v,
//             Err(e) => {
//                 break;
//             }
//         };
//
//     }
//
// }