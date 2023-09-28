#![allow(dead_code)]
#![allow(unused_variables)]
extern crate anyhow;
extern crate chacha20poly1305;
extern crate rand;
extern crate rsa;
extern crate sha2;
extern crate bimap;
extern crate der;
use bimap::BiHashMap;
use anyhow::{anyhow, bail, Result};
use rsa::RsaPublicKey;
use rsa::pss::{Signature, VerifyingKey};
use sha2::Sha256;
use signature::Verifier;
use rsa::pkcs8::DecodePublicKey;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 19;
const PUB_KEY_SER_LEN: usize = 550;
const SIGNATURE_LEN: usize = 512;
const PORT: &str = "2001";
const MAG_CONSTANT: [u8; 3] = [71, 78, 85];
const ENCRYPTED_KEY_LEN: usize = 512;
const CONFIRM_AUTH: u8 = 255;
const DENY_AUTH: u8 = 0;
const MAX_USERNAME_LEN: usize = 500;
const CODE_LEN: usize = 10;

const BUFFER_SIZE: usize = 512;

//Represents what the program is currently doing with the database and date key files
#[derive(Debug)]
pub enum FileAccess {
    Read,
    Write,
    Nothing,
}

//Codes signifying the reasons a client connects to the server
#[derive(Debug)]
enum ClientIntention {
    WriteData,
    DetermineRecipiency,
    FetchData,
    AlterClients,
}
//Associates ClientIntention with a u8
impl TryFrom<u8> for ClientIntention {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::WriteData),
            1 => Ok(Self::DetermineRecipiency),
            2 => Ok(Self::FetchData),
            3 => Ok(Self::AlterClients),
            _ => Err("Invalid number"),
        }
    }
}
impl From<ClientIntention> for u8 {
    fn from(value: ClientIntention) -> Self {
        match value {
            ClientIntention::WriteData => 0,
            ClientIntention::DetermineRecipiency => 1,
            ClientIntention::FetchData => 2,
            ClientIntention::AlterClients => 3,
        }
    }
}

pub fn reload_users(usernames_and_keys_path: &str) -> Result<(BiHashMap<String, RsaPublicKey>, Vec<RsaPublicKey>)> {
    let mut usernames_and_keys = File::open(usernames_and_keys_path)
        .map_err(|err| anyhow!("Failed to open users file at {usernames_and_keys_path}: {err}"))?;

    let mut users: BiHashMap<String, RsaPublicKey> = BiHashMap::new();
    let mut admin_users: Vec<RsaPublicKey> = Vec::new();
    
    loop {

        //Read admin flag
        let mut admin_buf = [0u8; 1];
        let read_count = usernames_and_keys.read(&mut admin_buf)
            .map_err(|err| anyhow!("Error reading admin flag from users file {usernames_and_keys_path}: {err}"))?;
        //If we cannot read a byte, it means that the file is over
        if read_count != 1 {
            break;
        }
        let admin = admin_buf == [255u8];

        //Read public key
        let mut pub_key_buf = [0u8; PUB_KEY_SER_LEN];
        let read_count = usernames_and_keys.read(&mut pub_key_buf)
            .map_err(|err| anyhow!("Error reading public key from users file {usernames_and_keys_path}: {err}"))?;
        if read_count != PUB_KEY_SER_LEN {
            bail!("Eror reading public key from users file {usernames_and_keys_path}. Tried to read {PUB_KEY_SER_LEN} bytes, actually read {read_count} bytes");
        }
        let pub_key = RsaPublicKey::from_public_key_der(&pub_key_buf)
            .map_err(|err| anyhow!("Public key in file {usernames_and_keys_path} invalid: {err}"))?;
        
        //Add public key to admin vector if admin flag is set
        if admin {
            admin_users.push(pub_key.clone());
        }

        //Read username length
        let mut username_len_buf = [0u8; 8];
        let read_count = usernames_and_keys.read(&mut username_len_buf)
            .map_err(|err| anyhow!("Error reading username length from users file {usernames_and_keys_path}: {err}"))?;
        if read_count != 8 {
            bail!("Eror reading username length from users file {usernames_and_keys_path}. Tried to read 8 bytes, actually read {read_count} bytes");
        }
        let username_len = u64::from_be_bytes(username_len_buf) as usize;
        
        //Read username
        let mut username_buf = vec![0u8; username_len];
        let read_count = usernames_and_keys.read(&mut username_buf)
            .map_err(|err| anyhow!("Error reading username from users file {usernames_and_keys_path}: {err}"))?;
        if read_count != username_len {
            bail!("Eror reading username from users file {usernames_and_keys_path}. Tried to read {username_len} bytes, actually read {read_count} bytes");
        }
        let username: String = String::from_utf8(username_buf)
            .map_err(|err| anyhow!("Could not create string from username data: {err}"))?;

        //Add username and public key to hashmap
        users.insert(username, pub_key);
    }
    Ok((users, admin_users))
}

//Removes a client from the users file. Does not reload the in-memory users list
pub fn remove_client(usernames_and_keys_path: &str, client: RsaPublicKey) -> Result<()> {
    let mut usernames_and_keys_file = File::options()
        .open(usernames_and_keys_path)
        .map_err(|err| anyhow!("Failed to open client file {usernames_and_keys_path} to remove client: {err}. Deletion aborted"))?;
    let mut pub_key_buf = [0u8; PUB_KEY_SER_LEN];
    let mut username_len_buf = [0u8; 8];
    loop {
        //Skip over admin flag
        usernames_and_keys_file.seek(SeekFrom::Current(1))
            .map_err(|err| anyhow!("Error reading admin confirmation byte. User may not be in users file: {err}. Deletion aborted"))?;

        //Read public key
        let read_count = usernames_and_keys_file.read(&mut pub_key_buf)
            .map_err(|err| anyhow!("Failed to read from client file {usernames_and_keys_path}: {err}. Deletion aborted"))?;
        if read_count != PUB_KEY_SER_LEN {
            bail!("Failed to read from client file {usernames_and_keys_path}. Tried to read {PUB_KEY_SER_LEN} bytes, actually read {read_count} bytes. Deletion aborted");
        }
        let pub_key = RsaPublicKey::from_public_key_der(&pub_key_buf)
        .map_err(|err| anyhow!("Error reconstructing public key from bytes from client file. The file is malformed: {err}. Deletion aborted"))?;

        //Check if this is the one to remove
        if pub_key == client {
            //If so, read username length
            let read_count = usernames_and_keys_file.read(&mut username_len_buf)
                .map_err(|err| anyhow!("Failed to read from client file {usernames_and_keys_path}: {err}. Deletion aborted"))?;
            if read_count != 8 {
                bail!("Failed to read from client file {usernames_and_keys_path}. Tried to read 8 bytes, actually read {read_count} bytes. Deletion aborted");
            }
            let username_len = u64::from_be_bytes(username_len_buf);
            let entry_length = 1+PUB_KEY_SER_LEN+8+username_len as usize;

            //Seek to end of entry to be deleted
            let position = usernames_and_keys_file.seek(SeekFrom::Current(username_len as i64))
                .map_err(|err| anyhow!("Failed to seek back to beginning of entry to remove in users file. Deletion aborted"))?;


            //Copy file, edit copy, then move back, to ensure atomicity
            std::fs::copy(usernames_and_keys_path, "/tmp/username_and_keys_copy")
                .map_err(|err| anyhow!("Failed to copy users file to delete user atomically. Deletion aborted"))?;
            let mut usernames_and_keys_copy = File::options()
                .write(true)
                .open("/tmp/username_and_keys_copy")
                .map_err(|err| anyhow!("Failed to open client file {usernames_and_keys_path} to remove client: {err}. Deletion aborted"))?;
            let file_length = usernames_and_keys_copy.metadata()
                .map_err(|err| anyhow!("Error getting metadata for temporary file for deleting user: {err}. Deletion aborted"))?
                .len();
            usernames_and_keys_copy.seek(SeekFrom::Start(position))
                .map_err(|err| anyhow!("Failed to seek to start of entry to remove in users file. Deletion aborted"))?;

            loop {
                //Shift all data in file back over deleted entry
                let mut buffer = vec![0u8; entry_length];
                //Read data
                let read_count = usernames_and_keys_copy.read(&mut buffer)
                    .map_err(|err| anyhow!("Error reading data to shift back over deleted entry: {err}. Deletion aborted"))?;
                if read_count != entry_length {
                    bail!(anyhow!("Error reading data to shift back over deleted entry. Tried to read {entry_length} bytes, actually read {read_count} bytes. Deletion aborted"));
                }
                //Seek back one entry
                let current_position = usernames_and_keys_copy.seek(SeekFrom::Current(-(entry_length as i64)))
                    .map_err(|err| anyhow!("Error seeking back in file to delete entry: {err}. Deletion aborted"))?;
                //Write data back
                let write_count = usernames_and_keys_copy.write(&buffer)
                    .map_err(|err| anyhow!("Error writing data over deleted entry: {err}. Deletion aborted"))?;
                if write_count != entry_length {
                    bail!(anyhow!("Error writing data over deleted entry. Tried to write {entry_length} bytes, actually wrote {write_count} bytes. Deletion aborted"));
                }
                //Seek to next entry, ending if there is no next entry
                if current_position+entry_length as u64 >= file_length {
                    usernames_and_keys_copy.set_len(file_length-entry_length as u64)
                        .map_err(|err| anyhow!("Error truncating file after deleting user: {err}. Deletion aborted"))?;
                    break;
                }
                usernames_and_keys_copy.seek(SeekFrom::Current(2*entry_length as i64))
                    .map_err(|err| anyhow!("Error seeking forward to next entry to shift back when deleting user: {err}. Deletion aborted"))?;
            }
            std::fs::rename("/tmp/usernames_and_keys_copy", usernames_and_keys_path)
                .map_err(|err| anyhow!("Error renaming new users file over old: {err}. Deletion aborted"))?;
            break;
            
        }
    }
    Ok(())
}

pub fn update_client_list(
    mut client_stream: TcpStream,
    usernames_and_keys: &mut BiHashMap<String, RsaPublicKey>,
    usernames_and_keys_path: &str
    ) -> Result<()> {

    //Value arbitrary and gets overwritten, but can't be 0, so it can be detected if the real value isn't read
    let mut add_buf = [6u8; 1];
    let read_count = client_stream.read(&mut add_buf)
        .map_err(|err| anyhow!("Failed to read whether to add or remove client: {err}"))?;
    if read_count != 1 {
        bail!("Failed to read whether to add or remove client. Tried to read 1 byte, actually read {read_count} bytes");
    };
    let add = match add_buf {
        [255] => true,
        [0] => false,
        _ => bail!("Received value for whether to add or remove client is invalid"),
    };
    let mut pub_key_buf = [0u8; PUB_KEY_SER_LEN];
    let read_count = client_stream.read(&mut pub_key_buf)
        .map_err(|err| anyhow!("Failed to read public key of altered user from client: {err}"))?;
    if read_count != PUB_KEY_SER_LEN {
        bail!("Failed to read public key of altered user from client. Tried to read {PUB_KEY_SER_LEN} bytes, actually read {read_count} bytes");
    }
    
    let mut username_len_buf = [0u8; 8];
    let read_count = client_stream.read(&mut username_len_buf)
        .map_err(|err| anyhow!("Failed to read username length of altered user from client: {err}"))?;
    if read_count != 8 {
        bail!("Failed to read username length of altered user from client. Tried to read 8 bytes, actually read {read_count} bytes");
    }
    let username_len = u64::from_be_bytes(username_len_buf);
    let mut username_buf = vec![0u8; username_len as usize];
    let read_count = client_stream.read(&mut username_buf)
        .map_err(|err| anyhow!("Failed to read username of altered user from client: {err}"))?;
    if read_count != username_len as usize {
        bail!("Failed to read username of altered user from client. Tried to read {username_len} bytes, actually read {read_count} bytes");
    }

    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_buf)
        .map_err(|err| anyhow!("Error reconstructing public key from bytes sent from newly initialising client: {err}"))?;
    let username = String::from_utf8(username_buf.clone())
        .map_err(|err| anyhow!("Error reconstructing username from bytes sent from newly initialising client: {err}"))?;

    let client = (username, pub_key);

    if add {
        let code = generate_client_reg_code();
        let code_buf = code.to_be_bytes();
        let write_count = client_stream.write(&code_buf)
            .map_err(|err| anyhow!("Error writing authentication code for new client to admin: {err}"))?;
        if write_count != 4 {
            bail!("Error writing authentication code for new client to admin. Tried to send 4 bytes, actually sent {write_count} bytes");
        }
        register_client(code, usernames_and_keys_path)?;
        loop {
            usernames_and_keys.insert(client.0, client.1);
            return Ok(());
        }
    }
    else {
        remove_client(usernames_and_keys_path, client.1)
            .map_err(|err| anyhow!("Error while removing client {}: {err}", client.0))?;
        usernames_and_keys.remove_by_left(&client.0);
        return Ok(());
    }
}

//Receives and stores messages sent from clients
//File specifications: date_keys consists of:
//timestamp (unix time): 8 bytes
//database index: 8 bytes
//This means the max size for the database of messages is 2305 petabytes. This is unlikely to be a
//problem
//The timestamp and and index for each message are all just stored sequentially.
//database consists of all messages, stored sequentially.
pub fn receive_and_store(
    mut client_stream: TcpStream,
    date_key_path: &str,
    database_path: &str,
) -> Result<()> {
    let mut current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| anyhow!("System time is earlier than UNIX epoch. Somehow. : {err}"))?
        .as_nanos() as u64;
    let mut database = File::options()
        .append(true)
        .open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    let database_len = database
        .metadata()
        .map_err(|err| {
            anyhow!("Could not access metadata for database file at path {database_path}: {err}")
        })?
        .len();

    let mut date_keys = File::options()
        .append(true)
        .read(true)
        .open(date_key_path)
        .map_err(|err| anyhow!("Could not open data key file at path {date_key_path}: {err}"))?;
    let date_keys_len = date_keys
        .metadata()
        .map_err(|err| {
            anyhow!("Could not access metadata for date_keys file at path {date_key_path}: {err}")
        })?
        .len();
    //Read the time of the last message stored.
    if database_len >= 16 {
        let mut last_message_time = [0u8; 8];
        date_keys.seek(SeekFrom::End(-16)).map_err(|err| {
            anyhow!(
                "Could not seek to end-16 bytes in date key file at path {date_key_path}: {err}"
            )
        })?;

        date_keys.read(&mut last_message_time).map_err(|err| {
            anyhow!("Could not read date key file at path {date_key_path}: {err}")
        })?;

        //Makes sure the current time is later than the last message time. This could be a problem if
        //multiple messages were stored in the same nanosecond.
        let last_message_time = u64::from_be_bytes(last_message_time);
        if current_time <= last_message_time {
            current_time = last_message_time + 1;
        }
    }

    //Opens the database and date keys file for appending
    date_keys
        .write(&current_time.to_be_bytes())
        .map_err(|err| {
            anyhow!(
                "Could not write current time into data key file at path {date_key_path}: {err}"
            )
        })?;
    date_keys.write(&(database_len).to_be_bytes())
        .map_err(|err| anyhow!("Could not write index for message into data key file at path {date_key_path}: {err}"))?;
    println!("Wrote timestamp {current_time} and index {database_len} at position {}, which is off by {} and equivalent to {}", date_keys_len, date_keys_len%16, date_keys_len/16);

    //Reads key count from client
    let mut key_count_buf = [0u8; 8];
    let read_count = client_stream
        .read(&mut key_count_buf)
        .map_err(|err| anyhow!("Error reading key count from client: {err}."))?;
    if read_count < 8 {
        bail!("Error reading key count from client. Tried to read 8 bytes, actually read {read_count} bytes.");
    }
    database.write(&key_count_buf)
        .map_err(|err| anyhow!("Error writing key count to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    let key_count = u64::from_be_bytes(key_count_buf);
    println!("key count {key_count}");

    //Read keys from client
    for _ in 0..key_count {
        let mut key_buf = [0u8; ENCRYPTED_KEY_LEN];
        let read_count = client_stream
            .read(&mut key_buf)
            .map_err(|err| anyhow!("Error reading keys from client: {err}."))?;
        if read_count < ENCRYPTED_KEY_LEN {
            bail!("Error reading keys from client. Tried to read {ENCRYPTED_KEY_LEN} bytes, actually read {read_count} bytes.");
        }
        database.write(&key_buf)
            .map_err(|err| anyhow!("Error writing keys to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    }

    //Read message length from client. This is stored in plaintext
    let mut message_len_buf = [0u8; 8];
    let read_count = client_stream
        .read(&mut message_len_buf)
        .map_err(|err| anyhow!("Error reading message length from client: {err}."))?;
    if read_count < 8 {
        bail!("Error reading message length from client. Tried to read 8 bytes, actually read {read_count} bytes.");
    }
    database.write(&message_len_buf)
        .map_err(|err| anyhow!("Error writing message length to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    let message_len = u64::from_be_bytes(message_len_buf);
    println!("message length {message_len}");

    //Read file count from client. This is stored in plaintext
    let mut file_count_buf = [0u8; 8];
    let read_count = client_stream
        .read(&mut file_count_buf)
        .map_err(|err| anyhow!("Error reading file count from client: {err}."))?;
    if read_count < 8 {
        bail!("Error reading file count from client. Tried to read 8 bytes, actually read {read_count} bytes.");
    }
    database.write(&file_count_buf)
        .map_err(|err| anyhow!("Error writing file count to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    let file_count = u64::from_be_bytes(file_count_buf);
    println!("file count {file_count}");

    //Reads message from client and saves it to the database.
    let mut buffer = [0u8; BUFFER_SIZE + 16];
    for _ in 0..message_len / (BUFFER_SIZE + 16) as u64 + 1 {
        let read_count = client_stream.read(&mut buffer)
            .map_err(|err| anyhow!("Error reading message data from client: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;

        database.write(&buffer)
            .map_err(|err| anyhow!("Error writing message data to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    }
    println!("database length {}", database.metadata()?.len());

    Ok(())
}

//Should be run on a seperate thread. Detects attempted connections from a client and spawns
//threads to handle them. Never exits.
pub fn monitor_connections(
    date_key_path: String,
    database_path: String,
    server_address: SocketAddr,
    usernames_and_keys: Arc<Mutex<(BiHashMap<String, rsa::RsaPublicKey>, Vec<RsaPublicKey>)>>,
    usernames_and_keys_path: String,
) -> Result<()> {
    let listener = TcpListener::bind(server_address)
        .map_err(|err| anyhow!("Could not bind a tcp listener to port 2001: {err}"))?;
    let file_access = Arc::new(Mutex::new(FileAccess::Nothing));
    let user_file_access = Arc::new(Mutex::new(()));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let date_key_path = date_key_path.clone();
                let database_path = database_path.clone();
                let usernames_and_keys_path = usernames_and_keys_path.clone();
                let file_access_clone = Arc::clone(&file_access);
                let user_file_access_clone = Arc::clone(&user_file_access);
                let usernames_and_keys = Arc::clone(&usernames_and_keys);
                    
                thread::spawn(move || {
                    let _ = handle_new_connection(
                        stream,
                        date_key_path.as_str(),
                        database_path.as_str(),
                        file_access_clone,
                        user_file_access_clone,
                        usernames_and_keys,
                        usernames_and_keys_path.as_str(),
                    )
                    .map_err(|err| {println!("{err}")});
                });
            }
            Err(_) => continue,
        }
    }
    unreachable!()
}

//Takes a new connection and authenticates it before handing it to the appropriate function
pub fn handle_new_connection(
    mut client_stream: TcpStream,
    date_key_path: &str,
    database_path: &str,
    file_access: Arc<Mutex<FileAccess>>,
    user_file_access: Arc<Mutex<()>>,
    mut usernames_and_keys: Arc<Mutex<(BiHashMap<String, rsa::RsaPublicKey>, Vec<RsaPublicKey>)>>,
    usernames_and_keys_path: &str,
) -> Result<()> {
    let rand_bytes: u64 = rand::random();

    //Writes random bytes to the client. The client will sign them and send them back.
    let write_count = client_stream
        .write(&rand_bytes.to_be_bytes())
        .map_err(|err| anyhow!("Error writing random bytes to be signed to client: {err}"))?;
    if write_count != 8 {
        bail!("Error writing random bytes to be signed to client. Sent the wrong number of bytes. Should have sent 8 bytes, actually sent {write_count} bytes");
    }

    let mut buf = [0u8; PUB_KEY_SER_LEN + SIGNATURE_LEN];
    let read_count = client_stream.read(&mut buf)
        .map_err(|err| anyhow!("Error reading public key and signature from client while they authenticate themselves: {err}"))?;
    if read_count != PUB_KEY_SER_LEN + SIGNATURE_LEN {
        bail!("Error reading public key and signature from client while they authenticate themselves. Expected to receive {} bytes, actually received {read_count} bytes", PUB_KEY_SER_LEN+SIGNATURE_LEN);
    }

    //Decode public key
    let pub_key = RsaPublicKey::from_public_key_der(&buf[..PUB_KEY_SER_LEN])
        .map_err(|err| anyhow!("Error recovering public key from received bytes: {err}"))?;

    //Decode signature
    let signature: Signature = buf[PUB_KEY_SER_LEN..PUB_KEY_SER_LEN + SIGNATURE_LEN]
        .to_vec()
        .into();

    let usernames_and_keys_lock = loop {
        let lock = usernames_and_keys.lock();
        match lock {
            Ok(i) => break i,
            Err(_) => { drop(lock);
                let usernames_and_keys_non_mutex = reload_users(usernames_and_keys_path)
                    .map_err(|err| anyhow!("Error reloading users from file after mutex poisoned: {err}"))?;
                usernames_and_keys = Arc::new(Mutex::new(usernames_and_keys_non_mutex)); },
        }
    };

    //Ensure public key is recognised
    let verifying_key: VerifyingKey<Sha256> = match usernames_and_keys_lock.0.contains_right(&pub_key) {
        true => VerifyingKey::from(pub_key.clone()),
        //If username is not recognised, deny
        false => {
            client_stream
                .write(&[DENY_AUTH])
                .map_err(|err| anyhow!("Error denying an incorrect send/receive code: {err}"))?;
            return Ok(());
        }
    };

    drop(usernames_and_keys_lock);

    //If signature does not match, deny
    if let Err(_) = verifying_key.verify(&rand_bytes.to_be_bytes(), &signature) {
        println!("ds");
        client_stream
            .write(&[DENY_AUTH])
            .map_err(|err| anyhow!("Error denying an incorrect send/receive code: {err}"))?;
        return Ok(());
    }
    println!("bs");

    //Otherwise confirm and find out what it wants
    client_stream
        .write(&[CONFIRM_AUTH])
        .map_err(|err| anyhow!("Error confirming send/receive code correct: {err}"))?;

    let mut intent_buf = [0u8; 1];
    client_stream
        .read(&mut intent_buf)
        .map_err(|err| anyhow!("Error receiving client intentions: {err}"))?;
    println!("cs");
    let intent: ClientIntention = u8::from_be_bytes(intent_buf).try_into().map_err(|_| {
        anyhow!(
            "Client sent invalid intent code {}",
            u8::from_be_bytes(intent_buf)
        )
    })?;
    println!("{intent:?}");

    match intent {
        ClientIntention::WriteData => {
            //Wait until no one is writing to or reading from the file
            loop {
                let mut file_access = file_access.lock().unwrap();
                if let FileAccess::Nothing = file_access.deref() {
                    *file_access.deref_mut() = FileAccess::Write;
                    break;
                }
                drop(file_access);
                sleep(Duration::from_millis(1));
            }
            let _ = receive_and_store(client_stream, date_key_path, database_path)
                .map_err(|err| println!("{err}"));
            //Say we are done with the file
            let mut file_access = file_access.lock().unwrap();
            *file_access.deref_mut() = FileAccess::Nothing;
        }
        ClientIntention::DetermineRecipiency => {
            //Wait until no one is writing to the file
            loop {
                let mut file_access = file_access.lock().unwrap();
                if let FileAccess::Write = file_access.deref() {
                } else {
                    *file_access.deref_mut() = FileAccess::Read;
                    break;
                }
                drop(file_access);
                sleep(Duration::from_millis(1));
            }
            let _ = handle_recipiency_query(client_stream, date_key_path, database_path)
                .map_err(|err| println!("{err}"));
            //Say we are done with the file
            let mut file_access = file_access.lock().unwrap();
            *file_access.deref_mut() = FileAccess::Nothing;
        }
        ClientIntention::FetchData => {
            //Wait until no one is writing to the file
            loop {
                let mut file_access = file_access.lock().unwrap();
                if let FileAccess::Write = file_access.deref() {
                } else {
                    *file_access.deref_mut() = FileAccess::Read;
                    break;
                }
                drop(file_access);
                sleep(Duration::from_millis(1));
            }
            let _ = send_message_data(client_stream, date_key_path, database_path)
                .map_err(|err| println!("{err}"));
            //Say we are done with the file
            let mut file_access = file_access.lock().unwrap();
            *file_access.deref_mut() = FileAccess::Nothing;
        }
        ClientIntention::AlterClients => {
            println!("as");
            let mut usernames_and_keys_lock = loop {
                let lock = usernames_and_keys.lock();
                match lock {
                    Ok(i) => break i,
                    Err(_) => { drop(lock);
                        let usernames_and_keys_non_mutex = reload_users(usernames_and_keys_path)
                            .map_err(|err| anyhow!("Error reloading users from file after mutex poisoned: {err}"))?;
                        usernames_and_keys = Arc::new(Mutex::new(usernames_and_keys_non_mutex)); },
                }
            };
            //Authenticate as admin
            if !usernames_and_keys_lock.1.contains(&pub_key) {
                println!("Denied");
                client_stream.write(&[DENY_AUTH])
                    .map_err(|err| anyhow!("Failed to send message denying admin authorisation: {err}"))?;
                return Ok(());
            }
            //Grant access
            client_stream.write(&[CONFIRM_AUTH])
                .map_err(|err| anyhow!("Failed to send message denying admin authorisation: {err}"))?;
            //Wait until no one is writing to the users file
            let user_file_access = user_file_access.lock().unwrap();
            let _ = update_client_list(client_stream, &mut usernames_and_keys_lock.deref_mut().0, usernames_and_keys_path)
                .map_err(|err| println!("{err}"));
            drop(usernames_and_keys_lock);
            //Say we are done with the file
            drop(user_file_access);
        }
    };
    Ok(())
}

//Takes a timestamp, and looks up the index of the message with the lowest timestamp greater than
//it. Returns Ok(None) if there is no message with timestamp greater than the one provided.
//Returns the index and timestamp otherwise. If exact is true, it locates a message with exactly
//that timestamp.
fn locate_index_from_timestamp(
    timestamp: u64,
    date_key_path: &str,
    exact: bool,
) -> Result<Option<(u64, u64)>> {
    //Opens the date keys file and gets the length. Length is in units of 16 bytes.
    let mut date_keys = File::open(date_key_path)
        .map_err(|err| anyhow!("Could not open date key file at path {date_key_path}: {err}"))?;
    let date_keys_len = date_keys
        .metadata()
        .map_err(|err| {
            anyhow!("Could not access metadata for date keys file at path {date_key_path}: {err}")
        })?
        .len()
        / 16;
    //If date keys file is empty no message matches
    if date_keys_len == 0 {
        return Ok(None);
    }

    //Binary search
    let index;
    let mut low = 0;
    let mut high = date_keys_len - 1;
    let exact_timestamp;
    let mut position = (low + high) / 2;
    let mut buf = [0u8; 8];
    let mut time;
    loop {
        date_keys
            .seek(SeekFrom::Start(position * 16))
            .map_err(|err| {
                anyhow!(
                    "Could not seek {} in date key file at path {date_key_path}: {err}",
                    position * 16
                )
            })?;
        let read_count = date_keys.read(&mut buf).map_err(|err| {
            anyhow!("Could not read date key file at path {date_key_path}: {err}")
        })?;
        if read_count < buf.len() {
            bail!("Date key file at path {date_key_path} is malformed. Could not read timestamp");
        }
        time = u64::from_be_bytes(buf);
        println!("Considered {time}");
        match time.cmp(&timestamp) {
            Ordering::Equal => {
                //If we are looking for an exact timestamp, this is the message
                if exact {
                    //Read index of entry
                    let read_count = date_keys.read(&mut buf).map_err(|err| {
                        anyhow!("Could not read date key file at path {date_key_path}: {err}")
                    })?;
                    if read_count < buf.len() {
                        bail!("Date key file at path {date_key_path} is malformed. Could not read index. Tried to read {}, read {read_count}.", buf.len());
                    }
                    index = u64::from_be_bytes(buf.clone());
                    exact_timestamp = timestamp;
                    println!("Found timestamp {exact_timestamp} and index {index} at position {position}. Length is {date_keys_len}");
                    break;
                }
                //If equal, find the next timestamp
                if position == date_keys_len - 1 {
                    return Ok(None);
                }
                //Otherwise, Skip this index, and read the timestamp of the next entry
                date_keys.seek(SeekFrom::Current(8))
                    .map_err(|err| anyhow!("Could not seek to 16 bytes ahead in date key file at path {date_key_path}: {err}"))?;
                let read_count = date_keys.read(&mut buf).map_err(|err| {
                    anyhow!("Could not read date key file at path {date_key_path}: {err}")
                })?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed. Could not read next timestamp. Tried to read {}, read {read_count}.", buf.len());
                }
                exact_timestamp = u64::from_be_bytes(buf.clone());

                //Read index of next entry
                let read_count = date_keys.read(&mut buf).map_err(|err| {
                    anyhow!("Could not read date key file at path {date_key_path}: {err}")
                })?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed. Could not read next index. Tried to read {}, read {read_count}.", buf.len());
                }
                index = u64::from_be_bytes(buf.clone());
                println!("Found timestamp {exact_timestamp} and index {index} at position {position}. Length is {date_keys_len}");
                break;
            }
            //If less, check if the next one is more. If it is, that is the one. Otherwise, keep
            //looking
            Ordering::Less => {
                println!("a{position}");
                println!("b{date_keys_len}");
                //If at end of file, bail out
                if position == date_keys_len - 1 {
                    return Ok(None);
                }
                //If we are looking for an exact timestamp, keep looking
                if exact {
                    low = position + 1;
                    let new_position = (low + high) / 2;
                    if new_position == position {
                        return Ok(None);
                    }
                    position = new_position;
                    continue;
                }
                //Otherwise, Skip this index, and read the timestamp of the next entry
                date_keys.seek(SeekFrom::Current(8))
                    .map_err(|err| anyhow!("Could not seek to 16 bytes ahead in date key file at path {date_key_path}: {err}"))?;
                let read_count = date_keys.read(&mut buf).map_err(|err| {
                    anyhow!("Could not read date key file at path {date_key_path}: {err}")
                })?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed. Could not read next timestamp. Tried to read {}, read {read_count}.", buf.len());
                }
                let next_time = u64::from_be_bytes(buf.clone());
                println!(" next time {next_time}");

                //Read the index of the next entry
                let read_count = date_keys.read(&mut buf).map_err(|err| {
                    anyhow!("Could not read date key file at path {date_key_path}: {err}")
                })?;
                if read_count < buf.len() {
                    bail!("Date key file at path {date_key_path} is malformed. Could not read next index. Tried to read {}, read {read_count}.", buf.len());
                }
                let next_index = u64::from_be_bytes(buf.clone());
                if next_time > timestamp {
                    index = next_index;
                    exact_timestamp = next_time;
                    println!("Found timestamp {exact_timestamp} and index {index} at position {position}. Length is {date_keys_len}");
                    break;
                }
                low = position + 1;
                let new_position = (low + high) / 2;
                if new_position == position {
                    return Ok(None);
                }
                position = new_position;
            }
            //If greater, keep looking unless we are at the start of the file
            Ordering::Greater => {
                //If at start of file, we want the first message then we can exit
                if position == 0 {
                    //If looking for an exact timestamp, this means failure
                    if exact {
                        return Ok(None);
                    }
                    exact_timestamp = time;
                    let read_count = date_keys.read(&mut buf).map_err(|err| {
                        anyhow!("Could not read date key file at path {date_key_path}: {err}")
                    })?;
                    if read_count < buf.len() {
                        bail!("Date key file at path {date_key_path} is malformed");
                    }
                    index = u64::from_be_bytes(buf.clone());
                    println!("Found timestamp {exact_timestamp} and index {index} at position {position}. Length is {date_keys_len}");
                    break;
                }
                //Otherwise, keep looking
                high = position - 1;
                position = (low + high) / 2;
            }
        }
    }
    Ok(Some((index, exact_timestamp)))
}

//Handle a query for the recipient keys of the first message past a certain timestamp
fn handle_recipiency_query(
    mut client_stream: TcpStream,
    date_key_path: &str,
    database_path: &str,
) -> Result<Option<()>> {
    //Get timestamp from client
    let mut timestamp_buf = [0u8; 8];
    let read_count = client_stream.read(&mut timestamp_buf).map_err(|err| {
        anyhow!("Error reading timestamp for requested message from client: {err}")
    })?;
    if read_count < 8 {
        bail!("Failed to read timestamp of message: {read_count} bytes transmitted, expected 8");
    }
    let timestamp = u64::from_be_bytes(timestamp_buf);

    let mut existence_confirmation_buffer = [0u8; 1];
    println!("Sent timestamp {timestamp}");
    let index_timestamp = locate_index_from_timestamp(timestamp, date_key_path, false)?;
    if let Some(_) = index_timestamp {
        existence_confirmation_buffer = [255u8; 1];
    }
    //Let the client know if the message exists.
    let write_count = client_stream.write(&existence_confirmation_buffer)
        .map_err(|err| anyhow!("Error writing existence confirmation buffer {existence_confirmation_buffer:?} to client: {err}"))?;
    if write_count < existence_confirmation_buffer.len() {
        bail!("Failed to write existence confirmation buffer{existence_confirmation_buffer:?} to client: {write_count} bytes transmitted, expected 8");
    }

    //Exit if there is no message
    if existence_confirmation_buffer == [0] {
        return Ok(None);
    }

    let (index, exact_timestamp) = index_timestamp.unwrap();
    println!("Found index {index}");

    //Write exact timestamp
    let write_count = client_stream
        .write(&exact_timestamp.to_be_bytes())
        .map_err(|err| {
            anyhow!("Error writing exact timestamp {exact_timestamp} to client: {err}")
        })?;
    if write_count < 8 {
        bail!("Failed to write exact timestamp {exact_timestamp} to client: {write_count} bytes transmitted, expected 8");
    }

    let mut buf = [0u8; 8];
    //Open database file at index
    let mut database = File::open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    database.seek(SeekFrom::Start(index))
        .map_err(|err| anyhow!("Could not seek to index {index} of database file at path {database_path}. Either the database file or the date key file is malformed."))?;
    let len = database.metadata()?.len();
    if index >= len {
        bail!("Index too large. Date keys file at {date_key_path} is malformed and gave an incorrect index, or database has somehow been truncated. Index was {index}, database length was {len}");
    }

    //Read the number of keys
    let read_count = database
        .read(&mut buf)
        .map_err(|err| anyhow!("Could not read database file at path {database_path}: {err}"))?;
    if read_count < buf.len() {
        bail!("Database file at path {database_path} is malformed. Could not read key number. Tried to read {} bytes but received {read_count}", buf.len());
    }
    client_stream
        .write(&buf)
        .map_err(|err| anyhow!("Error writing key number to client: {err}"))?;
    let key_num = u64::from_be_bytes(buf);

    //Read and send all the keys
    let mut key_buf = [0u8; ENCRYPTED_KEY_LEN];
    for i in 0..key_num {
        println!("Reading key num {i}");
        let read_count = database.read(&mut key_buf).map_err(|err| {
            anyhow!("Could not read database file at path {database_path}: {err}")
        })?;
        if read_count < ENCRYPTED_KEY_LEN {
            bail!("Database file at path {database_path} is malformed. Could not read keys. Tried to read {ENCRYPTED_KEY_LEN} bytes but received {read_count}");
        }
        let write_count = client_stream
            .write(&key_buf)
            .map_err(|err| anyhow!("Error writing keys to client: {err}"))?;
        if write_count < ENCRYPTED_KEY_LEN {
            bail!("Could not write key to client. Tried to send {ENCRYPTED_KEY_LEN} bytes, sent {write_count}");
        }
    }
    Ok(Some(()))
}

pub fn send_message_data(
    mut client_stream: TcpStream,
    date_key_path: &str,
    database_path: &str,
) -> Result<Option<()>> {
    //Get timestamp from client
    let mut timestamp_buf = [0u8; 8];
    let read_count = client_stream.read(&mut timestamp_buf).map_err(|err| {
        anyhow!("Error reading timestamp for requested message from client: {err}")
    })?;
    if read_count < timestamp_buf.len() {
        bail!("Error reading timestamp for requested message from client: Not enough bytes sent. Wanted 8 bytes, got {read_count} bytes");
    }
    let timestamp = u64::from_be_bytes(timestamp_buf);

    //Get offset from client
    let mut offset_buf = [0u8; 8];
    client_stream
        .read(&mut offset_buf)
        .map_err(|err| anyhow!("Error reading offset for requested message from client: {err}"))?;
    if read_count < offset_buf.len() {
        bail!("Error reading offset for requested message from client: Not enough bytes sent. Wanted 8 bytes, got {read_count} bytes");
    }
    let offset = u64::from_be_bytes(offset_buf);
    println!("offset {offset}");

    //Locate index of data
    //The index just before the message
    let index_timestamp = locate_index_from_timestamp(timestamp, date_key_path, true)?;
    if let None = index_timestamp {
        return Ok(None);
    }
    let (index, _) = index_timestamp.unwrap();

    //Open database file at index plus offset
    let mut database = File::open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    database.seek(SeekFrom::Start(index+offset))
        .map_err(|err| anyhow!("Could not seek to index {index} of database file at path {database_path}. Either the database file or the date key file is malformed."))?;
    let database_len = database.metadata().unwrap().len();

    //A good buffer size; The encryption adds 16 bytes to each packet
    let mut buf = [0u8; BUFFER_SIZE + 16];
    let mut amount_to_send_buf = [0u8; 8];
    let mut amount_to_send;

    //Write data as long as the client will read it. Client writes back saying how much they want
    //each time.
    loop {
        client_stream.read(&mut amount_to_send_buf).map_err(|err| {
            anyhow!("Could not read client's request for how much data to send: {err}")
        })?;
        amount_to_send = u64::from_be_bytes(amount_to_send_buf);
        if amount_to_send == 0 {
            break;
        }
        if amount_to_send > buf.len() as u64 {
            bail!("Client asked for {amount_to_send} bytes of data when the buffer holds only {} bytes", buf.len());
        }
        let read_count = database
            .read(&mut buf[..amount_to_send as usize])
            .map_err(|err| {
                anyhow!("Could not read database file at path {database_path}: {err}")
            })?;
        if read_count < amount_to_send as usize {
            bail!("Database file at path {database_path} is malformed or client asked for too much data. Could not read full buffer. Client asked for {amount_to_send} bytes when I could send {read_count} bytes");
        }
        let write_count = client_stream
            .write(&buf[..amount_to_send as usize])
            .map_err(|err| anyhow!("Error writing data to client: {err}"))?;
        if write_count < amount_to_send as usize {
            bail!("Could not write all data to client. Tried to write {amount_to_send} bytes, actually wrote {write_count} bytes");
        }
    }
    Ok(Some(()))
}
pub fn generate_client_reg_code() -> u32 {
    rand::random()
}

pub fn register_client(code: u32, usernames_and_keys_path: &str) -> Result<(String, RsaPublicKey)> {
    let listener = TcpListener::bind(PORT)
        .map_err(|err| anyhow!("Error binding to port {PORT} to register client, {err}"))?;
    let (mut stream, _) = listener.accept()
        .map_err(|err| anyhow!("Error accepting connection to register client, {err}"))?;
    
    let mut code_buf = [0u8; 4];
    let read_count = stream.read(&mut code_buf)
        .map_err(|err| anyhow!("Failed to read code from client to register: {err}"))?;
    if read_count != 4 {
        bail!("Failed to read code from client to initialise as a client. Tried to read 4 bytes, actually read {read_count} bytes");
    }
    if u32::from_be_bytes(code_buf) != code {
        bail!("Client sent incorrect code");
    }    

    let mut admin_buf = [0u8; 1];
    let read_count = stream.read(&mut admin_buf)
        .map_err(|err| anyhow!("Failed to read admin flag from client to register: {err}"))?;
    if read_count != 1 {
        bail!("Failed to read admin flag from client to initialise as a client. Tried to read 1 byte, actually read {read_count} bytes");
    }

    let mut pub_key_buf = [0u8; PUB_KEY_SER_LEN];
    let read_count = stream.read(&mut pub_key_buf)
        .map_err(|err| anyhow!("Failed to read public key from client to register: {err}"))?;
    if read_count != PUB_KEY_SER_LEN {
        bail!("Failed to read public key from client to initialise as a client. Tried to read {PUB_KEY_SER_LEN} bytes, actually read {read_count} bytes");
    }
    
    let mut username_len_buf = [0u8; 8];
    let read_count = stream.read(&mut username_len_buf)
        .map_err(|err| anyhow!("Failed to read username length from client to register: {err}"))?;
    if read_count != 8 {
        bail!("Failed to read username length from client to initialise as a client. Tried to read 8 bytes, actually read {read_count} bytes");
    }
    let username_len = u64::from_be_bytes(username_len_buf);
    let mut username_buf = vec![0u8; username_len as usize];
    let read_count = stream.read(&mut username_buf)
        .map_err(|err| anyhow!("Failed to read username from client to register: {err}"))?;
    if read_count != username_len as usize {
        bail!("Failed to read username from client to initialise as a client. Tried to read {username_len} bytes, actually read {read_count} bytes");
    }

    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_buf)
        .map_err(|err| anyhow!("Error reconstructing public key from bytes sent from newly initialising client: {err}"))?;
    let username = String::from_utf8(username_buf.clone())
        .map_err(|err| anyhow!("Error reconstructing username from bytes sent from newly initialising client: {err}"))?;

    let mut usernames_and_keys_file = File::options()
        .append(true)
        .open(usernames_and_keys_path)
        .map_err(|err| anyhow!("Failed to open usernames and keys file to write to at path {usernames_and_keys_path}: {err}"))?;

    let write_count = usernames_and_keys_file.write(&[admin_buf.as_slice(), pub_key_buf.as_slice(), &username_len.to_be_bytes(), username_buf.as_slice()].concat())
        .map_err(|err| anyhow!("Error writing to usernames and keys file when initialising new client: {err}"))?;
    if write_count != 1+PUB_KEY_SER_LEN+8+username_len as usize {
        bail!("Error writing to usernames and keys file when initialising new client. Attempted to write {} bytes, actually wrote {write_count} bytes", 1+PUB_KEY_SER_LEN+8+username_len as usize);
    }

    Ok((username, pub_key))
}
