#![allow(dead_code)]
#![allow(unused_variables)]
extern crate chacha20poly1305;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{stream, Aead, NewAead, stream::Encryptor}};
extern crate rand;
extern crate anyhow;
extern crate rsa;
extern crate sha2;
use anyhow::{bail, anyhow, Result, Context};
use rand::{RngCore, rngs::{ThreadRng, OsRng}};
use std::thread;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};

mod send;
mod receive;
use send::*;
use receive::*;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 19;
const PORT: &str = "2001";
const MAG_CONSTANT: [u8; 3] = [71,78,85];
const ENCRYPTED_KEY_LEN: usize = 512;
const BUFFER_SIZE: usize = 512;

fn signature(message: &str, priv_key: &[u8]) -> String {
    unimplemented!();
}






#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //This only tests that the message and files were written, not that the contents are correct.
    //Comes in a pair with the
    fn encrypt_and_write_test() {
        println!("a");
        fs::write("/tmp/a", [0u8, 1u8, 2u8, 3u8]).unwrap();
        fs::write("/tmp/b", [4u8, 5u8, 6u8, 7u8, 8u8]).unwrap();
        println!("b");
        let bits = 4096;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|err| anyhow!("failed to generate a key: {}", err)).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        std::thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:2001").unwrap();
            for stream in listener.incoming() {
                let mut buffer = [0u8; 8000];
                let mut stream = stream.unwrap();
                loop {
                    stream.read(&mut buffer).unwrap();
                }
            }
        });
        println!("Entered");
        symmetric_encrypt_and_send("abc".as_bytes(), vec!["/tmp/a", "/tmp/b"],  "127.0.0.1".to_string(), vec![public_key]).unwrap();
        println!("Exited");
    }
    fn encrypt_decrypt_key() {
        let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|err| anyhow!("failed to generate a key: {}", err)).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
    }
}
