use crate::net::ssp::CipherSuite;
use crate::net::ssp::SspStream;
use crate::net::ssp::SspState;
use crate::net::ssp::Version;


pub fn main() {

    let au_privkey: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ];

    let mut alice: SspStream = SspStream::new(
        Version::Version1,
        CipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
        &au_privkey[..]
    ).unwrap();
    println!("Ok");
    let mut bob: SspStream = SspStream::new(
        Version::Version1,
        CipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
        &au_privkey[..]
    ).unwrap();
    println!("Ok");
    let mut buf: [u8; 1024] = [0; 1024];

    let (s, state): (usize, SspState) = alice.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (r, state): (usize, SspState) = bob.hello_phase_recv(&buf[..]).unwrap();
    let (s, state): (usize, SspState) = bob.hello_phase_send(&mut buf[..]).unwrap();

    let (r, state): (usize, SspState) = alice.hello_phase_recv(&buf[..]).unwrap();



}

pub fn printbytes(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
}

pub fn printbytesln(bytes: &[u8]) {
    printbytes(bytes);
    println!();
}