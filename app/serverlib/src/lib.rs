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
use rand::{RngCore, rngs::OsRng};
use std::thread;
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};
use std::fs::File;
use std::net::{TcpStream, TcpListener};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};
use std::time::{SystemTime, UNIX_EPOCH};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 19;
const PORT: &str = "2001";
const MAG_CONSTANT: [u8; 3] = [71,78,85];
const ENCRYPTED_KEY_LEN: usize = 512;

const BUFFER_SIZE: usize = 512;

//Receives and stores messages sent from clients
//File specifications: date_keys consists of:
//timestamp (unix time): 8 bytes
//database index: 8 bytes
//This means the max size for the database of messages is 2305 petabytes. This is unlikely to be a
//problem
//The timestamp and and index for each message are all just stored sequentially.
//database consists of all messages, stored sequentially.
pub fn receive_and_store(mut client_stream: TcpStream, date_key_path: &str, database_path: &str) -> Result<()> {

    let mut current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| anyhow!("System time is earlier than UNIX epoch. Somehow. : {err}"))?
        .as_secs();

    let mut last_message_time = [0u8; 8];
    {
    let mut date_keys = File::open(date_key_path)
        .map_err(|err| anyhow!("Could not open date key file at path {date_key_path}: {err}"))?;
    date_keys.seek(SeekFrom::End(-16))
        .map_err(|err| anyhow!("Could not seek to end-16 bytes in date key file at path {date_key_path}: {err}"))?;

    date_keys.read(&mut last_message_time)
        .map_err(|err| anyhow!("Could not read date key file at path {date_key_path}: {err}"))?;
    }

    let last_message_time = u64::from_be_bytes(last_message_time);
    if current_time <= last_message_time {
        current_time = last_message_time + 1;
    }

    let mut database = File::options()
        .append(true)
        .open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    let database_len = database.metadata()
        .map_err(|err| anyhow!("Could not access metadata for database file at path {database_path}: {err}"))?
        .len();

    let mut date_keys = File::options()
        .append(true)
        .open(date_key_path)
        .map_err(|err| anyhow!("Could not open data key file at path {date_key_path}: {err}"))?;
    date_keys.write(&current_time.to_be_bytes())
        .map_err(|err| anyhow!("Could not write current time into data key file at path {date_key_path}: {err}"))?;
    date_keys.write(&(database_len-1).to_be_bytes())
        .map_err(|err| anyhow!("Could not write index for message into data key file at path {date_key_path}: {err}"))?;
   
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let read_count = client_stream.read(&mut buffer)
        .map_err(|err| anyhow!("Error reading message data from client: {err}. The last entry in date_keys and however much message was written must be deleted."))?;

        database.write(&buffer[..read_count])
        .map_err(|err| anyhow!("Error writing message data to database: {err}. The last entry in date_keys and however much message was written must be deleted."))?;

        if read_count < BUFFER_SIZE {
            break;
        }
    }

    Ok(())
}

fn decrypt_key(encrypted_key: [u8; ENCRYPTED_KEY_LEN], priv_key: &RsaPrivateKey) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let decrypted_key_nonce = priv_key.decrypt(padding, &encrypted_key).expect("failed to decrypt");
    if decrypted_key_nonce.len() != (KEY_LEN+NONCE_LEN) {
        bail!("Decrypted key is the wrong length");
    }
    let (magic, key_nonce) = decrypted_key_nonce.split_at(MAG_CONSTANT.len());
    let (key, nonce) = key_nonce.split_at(KEY_LEN);
    Ok((magic.into(), key.into(), nonce.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
