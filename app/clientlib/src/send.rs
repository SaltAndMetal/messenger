use crate::*;
//Generates and encrypts several copies of the key and nonce
fn encrypt_keys(key: [u8; KEY_LEN], nonce: [u8; NONCE_LEN], pub_keys: Vec<RsaPublicKey>, rng: &mut ThreadRng) -> Result<Vec<Vec<u8>>> {
    let mut return_val = Vec::new();
    let mag_key: Vec<u8> = MAG_CONSTANT.iter().chain(key.iter()).chain(nonce.iter()).map(|v| *v).collect();
    let mag_key: [u8; MAG_CONSTANT.len()+KEY_LEN+NONCE_LEN] = mag_key.try_into().unwrap();
    for pub_key in pub_keys {
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        return_val.push(pub_key.encrypt(rng, padding, &mag_key.clone())
            .map_err(|err| anyhow!("Failed to encrypt symmetric key"))?);
    }
    return Ok(return_val)
}

//Does a lot of jobs. Should be refactored.
//1. Generate both symmetric and non-symmetric keys
//2. Set up a TCP connection to the server
//3. Asymmetrically encrypts several copies of the symmetric key for each recipient
//4. Sends the number of recipients
//5. Sends the encrypted copies of the keys.
//3. Symmetric encrypts, writes, and sends the message a chunk at a time.
//4. Reads, symmetric encrypts, writes, and sends any files a chunk at a time.
pub fn symmetric_encrypt_and_send(message: &[u8], filenames: Vec<&str>, dest_ip: String, recipient_pub_keys: Vec<RsaPublicKey>) -> Result<()> {
    //Initialises symmetric-key cryptography
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    //Initialises assymetric cryptography
    let bits = 4069;
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|err| anyhow!("failed to generate a key: {}", err))?;
    let public_key = RsaPublicKey::from(&private_key);

    //Initialises buffer
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut i = 0;

    //Opens connection to server
    let mut server_stream = TcpStream::connect_timeout(
        &(dest_ip.clone() + ":" + PORT)
        .parse()
        .map_err(|err| anyhow!("Invalid IP address {}: {}", dest_ip + ":" + PORT, err))?,
            std::time::Duration::from_secs(10))
        .map_err(|err| anyhow!("Failed to establish connection to server"))?;

    let recipient_count_bytes = (recipient_pub_keys.len() as u64).to_be_bytes();
    //Encrypts copies of the key and nonce.
    //Concatenates the constant, the key, and the nonce.
    let key_copies = encrypt_keys(key, nonce, recipient_pub_keys, &mut rng)?;

    //Adds the recipient count to the buffer
    for byte in recipient_count_bytes {
        if i >= BUFFER_SIZE {
            server_stream
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
                server_stream
                    .write(buffer.as_slice())
                    .map_err(|err| anyhow!("Could not write to server: {}", err))?;
                i = 0;
            }
            buffer[i] = byte;
            i += 1;
        }
    }
    
    //Closure for encrypting and writing a buffer
    let encrypt_and_write = |buffer: &[u8; BUFFER_SIZE], server_stream: &mut TcpStream, stream_encryptor: &mut Encryptor<_, _>| -> Result<()> {
        //Encrypt buffer
        let ciphertext = 
                stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Failed to encrypt buffer: {}", err))?;

        //Write encrypted buffer
        server_stream
            .write(ciphertext.as_slice())
            .map_err(|err| anyhow!("Could not write to server: {}", err))?;
        Ok(())
    };
    //Prepend message with its length
    let message_len = message.len().to_be_bytes();
    for byte in message_len {
        if i >= BUFFER_SIZE {
            encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
            i = 0;
        }
        buffer[i] = byte;
        i += 1;
    }

    //Send message
    for byte in message {
        if i >= BUFFER_SIZE {
            encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
            i = 0;
        }
        buffer[i] = *byte;
        i += 1;
    }

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
                encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
                i = 0;
            }
            buffer[i] = byte;
            i += 1;
        }
        server_stream
            .write(&buffer)
            .map_err(|err| anyhow!("Could not write length of file {} to server: {}", filename, err))?;

        //Send contents
        loop {
            let read_count = file
                .read(&mut buffer[i..])
                .map_err(|err| anyhow!("Could not read file {}: {}", filename, err))?;
            encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
            i = (BUFFER_SIZE - i - 1) - read_count;
            if i > 0 {
                break;
            }
        }
    }
    Ok(())
}
