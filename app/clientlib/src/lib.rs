#![allow(dead_code)]
#![allow(unused_variables)]
extern crate chacha20poly1305;
use chacha20poly1305::{
    aead::{stream, stream::Encryptor, NewAead},
    XChaCha20Poly1305,
};
extern crate anyhow;
extern crate bimap;
extern crate rand;
extern crate rsa;
extern crate sha2;
use anyhow::{anyhow, bail, Result};
use bimap::BiHashMap;
use rand::{
    rngs::{OsRng, ThreadRng},
    RngCore,
};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePublicKey;
use sha2::Sha256;
use signature::{RandomizedSigner, Verifier};
use std::cmp::Ordering;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::Deref;
use std::time::Duration;

mod receive;
mod send;
pub use receive::*;
pub use send::*;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 19;
const PRIV_KEY_SIZE: usize = 4096;
const PUB_KEY_SER_LEN: usize = 550;
const SIGNATURE_LEN: usize = 512;
const USERNAME_MAX_LEN: usize = 1000;
const PORT: &str = "2001";
const MAG_CONSTANT: [u8; 3] = [71, 78, 85];
const ENCRYPTED_KEY_LEN: usize = 512;
const BUFFER_SIZE: usize = 512;
const ADD: u8 = 255;
const REMOVE: u8 = 0;

const CONFIRM_AUTH: u8 = 255;

//Codes signifying the reasons a client connects to the server
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

//Generalised initialisation of server
fn init_server(server_ip: &SocketAddr, private_key: &RsaPrivateKey, public_key: &RsaPublicKey) -> Result<(TcpStream, [u8; 1])> {
    let mut stream = TcpStream::connect_timeout(server_ip, Duration::from_secs(5))
        .map_err(|err| anyhow!("Connection to server at address {server_ip} failed: {err}"))?;
    let mut buf = [0u8; 8];
    let read_count = stream
        .read(&mut buf)
        .map_err(|err| anyhow!("Error reading random bytes from server to sign: {err}"))?;
    if read_count != 8 {
        bail!("Error reading random bytes from server to sign. Should have read 8 bytes, actually read {read_count} bytes");
    }
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, &buf);
    println!("{}", signature.deref().len());
    let ser_key = public_key.to_public_key_der()
        .map_err(|err| anyhow!("Failed serialising public key to send to server to authenticate: {err}"))?;
    let ser_key = ser_key.as_bytes();

    let write_count = stream
        .write(
            &[
                ser_key,
                signature.deref(),
            ]
            .concat(),
        )
        .map_err(|err| anyhow!("Error writing signature and identity to the server: {err}"))?;
    if write_count != (PUB_KEY_SER_LEN + SIGNATURE_LEN) {
        bail!("Error writing signature and identity to the server. Tried to write {} bytes, actually wrote {write_count} bytes.", PUB_KEY_SER_LEN+SIGNATURE_LEN);
    }
    let mut conf_buf = [0u8; 1];
    stream
        .read(&mut conf_buf)
        .map_err(|err| anyhow!("Error receiving confirmation for sending code: {err}"))?;
    Ok((stream, conf_buf))
}

//This struct represents a server ready to recieve instructions to alter the user list
pub struct ServerUserAlterStream {
    stream: TcpStream,
}
impl ServerUserAlterStream {
    pub fn init_server(
        server_ip: &SocketAddr,
            private_key: &RsaPrivateKey,
            public_key: &RsaPublicKey,
        ) -> Result<Self> {
        let (mut stream, conf_buf) = init_server(server_ip, private_key, public_key)?;
        //If code is correct, the server fills the buffer with 1s to write back
        if conf_buf[0] == CONFIRM_AUTH {
            println!("heres");

            //Send intent
            let intent: u8 = ClientIntention::AlterClients.into();
            println!("about to send intent");
            stream
                .write(&intent.to_be_bytes())
                .map_err(|err| anyhow!("Error writing intent to the server: {err}"))?;
            println!("sent intent");

            //Authenticate
            let mut auth_conf_buf = [0u8; 1];
            stream
                .read(&mut auth_conf_buf)
                .map_err(|err| anyhow!("Error receiving confirmation for sending code: {err}"))?;
            println!("{auth_conf_buf:?}");

            if auth_conf_buf[0] != CONFIRM_AUTH {
                bail!("User is not an admin. Server denied connection");
            }
            Ok(Self{ stream })
        } else {
            bail!("Sending code was invalid. Server denied connection");
        }

    }
}

//This struct represents a server ready to send data from a message at a certain byte offset
pub struct ServerSendStream {
    stream: TcpStream,
    offset: u64,
}
impl ServerSendStream {
    //A server ready to send message data
    pub fn init_server(
        server_ip: &SocketAddr,
        offset: u64,
        timestamp: u64,
        private_key: &RsaPrivateKey,
        public_key: &RsaPublicKey,
    ) -> Result<Self> {
        let (mut stream, conf_buf) = init_server(server_ip, private_key, public_key)?;
        //If code is correct, the server fills the buffer with 1s to write back
        if conf_buf[0] == CONFIRM_AUTH {
            //Send intent
            let intent: u8 = ClientIntention::FetchData.into();
            stream
                .write(&intent.to_be_bytes())
                .map_err(|err| anyhow!("Error writing intent to the server: {err}"))?;
            //Send timestamp
            stream
                .write(&timestamp.to_be_bytes())
                .map_err(|err| anyhow!("Error writing the timestamp to the server: {err}"))?;
            //Send offset
            let offset_buf = offset.to_be_bytes();
            stream
                .write(offset_buf.as_slice())
                .map_err(|err| anyhow!("Error writing the offset to the server: {err}"))?;
            Ok(Self { stream, offset: 0 })
        } else {
            bail!("Sending code was invalid. Server denied connection");
        }
    }
}
//The struct represents a server ready to send the list of keys (recipients) for the oldest message
//younger than a certain timestamp, to be send later
pub struct ServerKeysStream {
    stream: TcpStream,
}
impl ServerKeysStream {
    pub fn init_server(server_ip: &SocketAddr, private_key: &RsaPrivateKey, public_key: &RsaPublicKey) -> Result<Self> {
        let (mut stream, conf_buf) = init_server(server_ip, private_key, public_key)?;
        //If code is correct, the server fills the buffer with 1s to write back
        if conf_buf[0] == CONFIRM_AUTH {
            //Send intent
            let intent: u8 = ClientIntention::DetermineRecipiency.into();
            stream
                .write(&intent.to_be_bytes())
                .map_err(|err| anyhow!("Error writing intent to the server: {err}"))?;
            Ok(Self { stream })
        } else {
            bail!("Sending code was invalid. Server denied connection");
        }
    }
}

//This struct represents a server ready to read the contents of a message sent by the client
#[derive(Debug)]
pub struct ServerRecieveStream {
    stream: TcpStream,
}
impl ServerRecieveStream {
    pub fn init_server(server_ip: &SocketAddr, private_key: &RsaPrivateKey, public_key: &RsaPublicKey) -> Result<Self> {
        let (mut stream, conf_buf) = init_server(server_ip, private_key, public_key)?;
        //If code is correct, the server fills the buffer with 1s to write back
        if conf_buf[0] == CONFIRM_AUTH {
            //Send intent
            let intent: u8 = ClientIntention::WriteData.into();
            stream
                .write(&intent.to_be_bytes())
                .map_err(|err| anyhow!("Error writing intent to the server: {err}"))?;
            Ok(Self { stream })
        } else {
            bail!("Sending code was invalid. Server denied connection");
        }
    }
}

pub fn first_init(server_ip: &SocketAddr, code: u32, username: &str) -> Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut stream = TcpStream::connect(server_ip)
        .map_err(|err| anyhow!("Could not connect to server at address {server_ip} to initialise as a client: {err}"))?;

    let write_count = stream.write(&code.to_be_bytes())
        .map_err(|err| anyhow!("Could not write code to server to initialise as a client: {err}"))?;
    if write_count != 4 {
        bail!("Failed to write code to server to initialise as a client. Tried to write 4 bytes, actually wrote {write_count} bytes");
    }

    let mut rng = rand::thread_rng();
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, PRIV_KEY_SIZE)
        .map_err(|err| anyhow!("Error generating private key while initialising as client"))?;
    let pub_key = rsa::RsaPublicKey::from(&priv_key);

    let ser_key = pub_key.to_public_key_der()
        .map_err(|err| anyhow!("Failed serialising public key to send to server to authenticate: {err}"))?;
    let ser_key = ser_key.as_bytes();

    let write_count = stream.write(&ser_key)
        .map_err(|err| anyhow!("Could not write public key to server to initialise as a client: {err}"))?;
    if write_count != PUB_KEY_SER_LEN {
        bail!("Failed to write public key to server to initialise as a client. Tried to write {PUB_KEY_SER_LEN} bytes, actually wrote {write_count} bytes");
    }

    let username = username.as_bytes();
    let len = username.len();
    let write_count = stream.write(&(len as u64).to_be_bytes())
        .map_err(|err| anyhow!("Could not write username length to server to initialise as a client: {err}"))?;
    if write_count != 8 {
        bail!("Failed to write username length to server to initialise as a client. Tried to write 8 bytes, actually wrote {write_count} bytes");
    }
    let write_count = stream.write(&username)
        .map_err(|err| anyhow!("Could not write username to server to initialise as a client: {err}"))?;
    if write_count != len {
        bail!("Failed to write username to server to initialise as a client. Tried to write {len} bytes, actually wrote {write_count} bytes");
    }
    Ok((pub_key, priv_key))
}
