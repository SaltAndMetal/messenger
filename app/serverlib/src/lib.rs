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
use std::cmp::Ordering;

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

    //Read the time of the last message stored. In a block so the date_keys file is closed after
    //reading.
    let mut last_message_time = [0u8; 8];
    {
    let mut date_keys = File::open(date_key_path)
        .map_err(|err| anyhow!("Could not open date key file at path {date_key_path}: {err}"))?;
    date_keys.seek(SeekFrom::End(-16))
        .map_err(|err| anyhow!("Could not seek to end-16 bytes in date key file at path {date_key_path}: {err}"))?;

    date_keys.read(&mut last_message_time)
        .map_err(|err| anyhow!("Could not read date key file at path {date_key_path}: {err}"))?;
    }

    //Makes sure the current time is later than the last message time. This could be a problem if
    //multiple messages were stored in the same second.
    let last_message_time = u64::from_be_bytes(last_message_time);
    if current_time <= last_message_time {
        current_time = last_message_time + 1;
    }

    //Opens the database and date keys file for appending
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
   
    //Reads message from client and saves it to the database.
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

//Handle a query for the recipient keys of the first message past a certain timestamp
fn handle_recipiency_query(mut client_stream: TcpStream, date_key_path: &str, database_path: &str, timestamp: u64) -> Result<Option<()>> {
    //Opens the date keys file and gets the length. Length is in units of 16 bytes.
    let mut date_keys = File::open(date_key_path)
        .map_err(|err| anyhow!("Could not open date key file at path {date_key_path}: {err}"))?;
    let date_keys_len = date_keys.metadata()
        .map_err(|err| anyhow!("Could not access metadata for date keys file at path {database_path}: {err}"))?
        .len()/16;

    //Binary search to find the timestamp
    let index;
    let mut position = date_keys_len/2;
    let mut buf = [0u8; 8];
    let mut time;
    loop {
        date_keys.seek(SeekFrom::Start(position*16))
            .map_err(|err| anyhow!("Could not seek to end-16 bytes in date key file at path {date_key_path}: {err}"))?;
        let read_count = date_keys.read(&mut buf)
            .map_err(|err| anyhow!("Could not read date key file at path {date_key_path}: {err}"))?;
        if read_count < buf.len() {
            bail!("Date key file at path {date_key_path} is malformed");
        }
        time = u64::from_be_bytes(buf);
        match time.cmp(&timestamp) {
            Ordering::Equal => {
                //If equal, find the next timestamp
                if position == date_keys_len {
                    return Ok(None);
                }
                let read_count = date_keys.read(&mut buf)
                    .map_err(|err| anyhow!("Could not read date key file at path {date_key_path}: {err}"))?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed");
                }
                index = u64::from_be_bytes(buf.clone());
                break;
            },
            //If less, check if the next one is more. If it is, that is the one. Otherwise, keep
            //looking
            Ordering::Less => {
                if position == date_keys_len {
                    return Ok(None);
                }
                let read_count = date_keys.read(&mut buf)
                    .map_err(|err| anyhow!("Could not read date key file at path {date_key_path}: {err}"))?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed");
                }
                let next = u64::from_be_bytes(buf.clone());
                if next > timestamp {
                    index = next;
                    break;
                }
                let new_position = (position + date_keys_len)/2;
                if new_position == position {
                    bail!("Timestamp not in date key file {date_key_path}");
                }
                position = new_position;
            },
            //If greater, keep looking
            Ordering::Greater => {
                let new_position = (position+0)/2;
                if new_position == position {
                    bail!("Timestamp not in date key file {date_key_path}");
                }
                position = new_position;
            },
            
        }
    }

    //Open database file at index
    let mut database = File::open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    database.seek(SeekFrom::Start(index))
        .map_err(|err| anyhow!("Could not seek to index {index} of database file at path {database_path}. Either the database file or the date key file is malformed."))?;

    //Read the number of keys
    let read_count = database.read(&mut buf)
        .map_err(|err| anyhow!("Could not read database file at path {database_path}: {err}"))?;
    if read_count < buf.len() {
        bail!("Database file at path {database_path} is malformed. Could not read key number");
    }
    client_stream.write(&buf)
        .map_err(|err| anyhow!("Error writing key number to client: {err}"))?;
    let key_num = u64::from_be_bytes(buf);

    //Read and send all the keys
    let mut key_buf = [0u8; ENCRYPTED_KEY_LEN];
    for _ in 0..key_num {
        let read_count = database.read(&mut key_buf)
            .map_err(|err| anyhow!("Could not read database file at path {database_path}: {err}"))?;
        if read_count < ENCRYPTED_KEY_LEN {
            bail!("Database file at path {database_path} is malformed. Could not read keys");
        }
        client_stream.write(&key_buf)
            .map_err(|err| anyhow!("Error writing keys to client: {err}"))?;
    }
    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
