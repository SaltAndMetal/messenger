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
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 19;
const PORT: &str = "2001";
const MAG_CONSTANT: [u8; 3] = [71,78,85];

const BUFFER_SIZE: usize = 512;

fn signature(message: &str, priv_key: &[u8]) -> String {
    unimplemented!();
}

//Does a lot of jobs. Should be refactored.
//1. Generate both symmetric and non-symmetric keys
//2. Set up a TCP connection to the server
//3. Asymmetrically encrypts several copies of the symmetric key for each recipient
//4. Sends the number of recipients
//5. Sends the encrypted copies of the keys.
//3. Symmetric encrypts, writes, and sends the message a chunk at a time.
//4. Reads, symmetric encrypts, writes, and sends any files a chunk at a time.
pub fn symmetric_encrypt_and_send(message: &[u8], filenames: Vec<&str>, destIP: String, recipient_pub_keys: Vec<RsaPublicKey>) -> Result<()> {
    //Initialises symmetric-key cryptography
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    println!("c");
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    println!("d");
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    println!("e");

    //Initialises assymetric cryptography
    let bits = 4069;
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|err| anyhow!("failed to generate a key: {}", err))?;
    let public_key = RsaPublicKey::from(&private_key);

    //Initialises buffer
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut i = 0;

    //Opens connection to server
    let mut TCPstream = TcpStream::connect_timeout(
        &(destIP.clone() + ":" + PORT)
        .parse()
        .map_err(|err| anyhow!("Invalid IP address {}: {}", destIP + ":" + PORT, err))?,
            std::time::Duration::from_secs(10))
        .map_err(|err| anyhow!("Failed to establish connection to server"))?;

    //Encrypts copies of the key and nonce.
    //Concatenates the constant, the key, and the nonce.
    let mag_key: Vec<u8> = MAG_CONSTANT.iter().chain(key.iter()).chain(nonce.iter()).map(|v| *v).collect();
    let mag_key: [u8; MAG_CONSTANT.len()+KEY_LEN+NONCE_LEN] = mag_key.try_into().unwrap();

    //Encrypts the different copies of the key.
    let mut key_copies = Vec::with_capacity(recipient_pub_keys.len());
    let recipient_count_bytes = (recipient_pub_keys.len() as u64).to_be_bytes();
    for key in recipient_pub_keys {
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        key_copies.push(key.encrypt(&mut rng, padding, &mag_key.clone()).expect("failed to encrypt"));
    }
    println!("{:#?}", key_copies[0].len());
    //Adds the recipient count to the buffer
    for byte in recipient_count_bytes {
        if i >= BUFFER_SIZE {
            TCPstream
                .write(buffer.as_slice())
                .map_err(|err| anyhow!("Could not write to server: {}", err))?;
            i = 0;
        }
        buffer[i] = byte;
        i += 1;
    }
    //Writes to server the key count.
    for key_copy in key_copies {
        for byte in key_copy {
            if i >= BUFFER_SIZE {
                TCPstream
                    .write(buffer.as_slice())
                    .map_err(|err| anyhow!("Could not write to server: {}", err))?;
                i = 0;
            }
            buffer[i] = byte;
            i += 1;
        }
    }
    
    //Closure for encrypting and writing a buffer
    let encrypt_and_write = |buffer: &[u8; BUFFER_SIZE], TCPstream: &mut TcpStream, stream_encryptor: &mut Encryptor<_, _>| -> Result<()> {
        //Encrypt buffer
        let ciphertext = 
                stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Failed to encrypt buffer: {}", err))?;

        //Write encrypted buffer
        TCPstream
            .write(ciphertext.as_slice())
            .map_err(|err| anyhow!("Could not write to server: {}", err))?;
        Ok(())
    };
    //Prepend message with its length
    let message_len = message.len().to_be_bytes();
    for byte in message_len {
        if i >= BUFFER_SIZE {
            encrypt_and_write(&buffer, &mut TCPstream, &mut stream_encryptor)?;
            i = 0;
        }
        buffer[i] = byte;
        i += 1;
    }

    //Send message
    for byte in message {
        if i >= BUFFER_SIZE {
            encrypt_and_write(&buffer, &mut TCPstream, &mut stream_encryptor)?;
            i = 0;
        }
        buffer[i] = *byte;
        i += 1;
    }
    println!("Message sent");

    //Send any files
    for filename in filenames {
        //Open file and get length
        let mut file = fs::File::open(filename)
            .map_err(|err| anyhow!("Could not open file {}: {}", filename, err))?;

        //Prepend file length
        let file_length_bytes = file
            .metadata()
            .map_err(|err| anyhow!("Could not read length of file {}: {}", filename, err))?
            .len()
            .to_be_bytes();

        for byte in file_length_bytes {
            if i >= BUFFER_SIZE {
                encrypt_and_write(&buffer, &mut TCPstream, &mut stream_encryptor)?;
                i = 0;
            }
            buffer[i] = byte;
            i += 1;
        }
        TCPstream
            .write(&buffer)
            .map_err(|err| anyhow!("Could not write length of file {} to server: {}", filename, err))?;
        println!("Metadata {filename} sent");

        //Send contents
        loop {
            let read_count = file
                .read(&mut buffer[i..])
                .map_err(|err| anyhow!("Could not read file {}: {}", filename, err))?;
            encrypt_and_write(&buffer, &mut TCPstream, &mut stream_encryptor)?;
            i = (BUFFER_SIZE - i - 1) - read_count;
            println!("{i}");
            if i > 0 {
                break;
            }
        }
        println!("Data {filename} sent");
    }
    Ok(())
}

fn read_message(stream: TcpStream, priv_key: RsaPrivateKey) -> Result<()> {
    enum ReadState {
        KeyNum,
        Keys,
        MessageLen,
        Message,
        FileLen,
        File,
    }
    type Position = (ReadState, usize);

    //A whole load of buffers and positions in those buffers
    let mut position: Position = (ReadState::KeyNum, 0);
    let mut key_num_bytes = [0u8; 8];
    let mut key_num = 0;
    let mut current_key = 0;
    let mut key_buf = [0u8; ENCRYPTED_KEY_LEN];
    let mut key_buf_pos = 0;
    let mut buf_pos = 0;
    let mut read_count = 0;
    'read: loop {
        if buf_pos == BUFFER_SIZE {
            read_count = client_stream.read(&mut buffer)
                .map_err(|err| anyhow!("Error receiving message from client: {err}"))?;
        }
        if read_count < BUFFER_SIZE {
            unimplemented!()
        }
        match position.0 { 
            ReadState::KeyNum => {
                while position.1 < 8 {
                    key_num_bytes[position.1] = buffer[buf_pos];
                    position.1 += 1;
                    buf_pos += 1;
                    if buf_pos == BUFFER_SIZE {
                        continue 'read;
                    }
                };
                key_num = u64::from_be_bytes(key_num_bytes);
                position.0 = ReadState::KeyNum;
                continue;
            },
            ReadState::Keys => {
                key_buf[key_buf_pos] = buffer[buf_pos];
                key_buf_pos += 1;
                buf_pos += 1;
                if key_buf_pos == ENCRYPTED_KEY_LEN {
                    let (magic, key, nonce) = decrypt_key(key_buf, &priv_key)?;

                }
            },
            _ => ()
        }
        break;
    }
    unimplemented!()
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
}
