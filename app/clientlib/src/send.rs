use crate::*;
//Generates and encrypts several copies of the key and nonce
fn encrypt_keys(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    pub_keys: Vec<&RsaPublicKey>,
    rng: &mut ThreadRng,
) -> Result<Vec<Vec<u8>>> {
    let mut return_val = Vec::new();
    let mag_key: Vec<u8> = MAG_CONSTANT
        .iter()
        .chain(key.iter())
        .chain(nonce.iter())
        .map(|v| *v)
        .collect();
    let mag_key: [u8; MAG_CONSTANT.len() + KEY_LEN + NONCE_LEN] = mag_key.try_into().unwrap();
    for pub_key in pub_keys {
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        return_val.push(
            pub_key
                .encrypt(rng, padding, &mag_key.clone())
                .map_err(|err| anyhow!("Failed to encrypt symmetric key"))?,
        );
    }
    return Ok(return_val);
}

//Does a lot of jobs. Should be refactored.
//1. Generate symmetric keys
//2. Set up a TCP connection to the server
//3. Asymmetrically encrypts several copies of the symmetric key for each recipient
//4. Sends the number of recipients
//5. Sends the encrypted copies of the keys.
//6. Signs the message
//7. Symmetric encrypts, writes, and sends the message a chunk at a time.
//8. Reads, symmetric encrypts, writes, and sends any files a chunk at a time.
pub fn symmetric_encrypt_and_send(
    message: &[u8],
    filenames: Vec<&str>,
    server_stream: ServerRecieveStream,
    recipient_pub_keys: Vec<&RsaPublicKey>,
    private_key: &RsaPrivateKey,
    username: &str,
) -> Result<()> {
    //Unwraps the stream to the server
    let mut server_stream = server_stream.stream;

    //Initialises symmetric-key cryptography
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut rng = rand::thread_rng();

    //Initialises key buffer. Makes sure all the keys are sent
    let mut key_buffer = [0u8; ENCRYPTED_KEY_LEN];
    let mut i = 0;

    let signing_key = SigningKey::<Sha256>::new(private_key.clone());

    let signature = signing_key.sign_with_rng(&mut rng, &message);
    let username = username.as_bytes();
    let message = [
        &(username.len() as u64).to_be_bytes(),
        username,
        signature.deref(),
        message,
    ]
    .concat();

    let recipient_count_bytes = (recipient_pub_keys.len() as u64).to_be_bytes();
    //Encrypts copies of the key and nonce.
    //Concatenates the constant, the key, and the nonce.
    let key_copies = encrypt_keys(key, nonce, recipient_pub_keys, &mut rng)?;
    println!("{}", key_copies[0].len());

    //Send server the key count
    server_stream
        .write(recipient_count_bytes.as_slice())
        .map_err(|err| anyhow!("Could not write key count to server: {err}"))?;

    //Writes to server the keys.
    for key_copy in key_copies {
        for byte in key_copy {
            key_buffer[i] = byte;
            i += 1;
            if i >= ENCRYPTED_KEY_LEN {
                server_stream
                    .write(key_buffer.as_slice())
                    .map_err(|err| anyhow!("Could not write to server: {err}"))?;
                i = 0;
            }
        }
    }

    if i != 0 {
        bail!("Key size is malformed. Was {i} bytes off");
    }
    //Send message length
    server_stream
        .write(&(message.len() as u64).to_be_bytes())
        .map_err(|err| anyhow!("Could not write message length to server: {err}"))?;
    println!("sent message length {}", message.len());
    //Send number of files
    server_stream
        .write(&(filenames.len() as u64).to_be_bytes())
        .map_err(|err| anyhow!("Could not write message length to server: {err}"))?;
    println!("sent file count {}", filenames.len());

    //Buffer for sending the rest of the messages. It is seperate because all the keys must be sent
    //first, as they are unencrypted
    let mut buffer = [0u8; BUFFER_SIZE];

    //Closure for encrypting and writing a buffer
    let encrypt_and_write = |buffer: &[u8; BUFFER_SIZE],
                             server_stream: &mut TcpStream,
                             stream_encryptor: &mut Encryptor<_, _>|
     -> Result<()> {
        //Encrypt buffer
        let ciphertext = stream_encryptor
            .encrypt_next(buffer.as_slice())
            .map_err(|err| anyhow!("Failed to encrypt buffer: {err}"))?;

        //Write encrypted buffer
        let write_count = server_stream
            .write(ciphertext.as_slice())
            .map_err(|err| anyhow!("Could not write to server: {err}"))?;
        Ok(())
    };

    //Send message
    for byte in message {
        buffer[i] = byte;
        i += 1;
        if i >= BUFFER_SIZE {
            encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
            i = 0;
        }
    }

    //If there are no files, it is the last buffer, so fill with 0s and flush.
    if filenames.len() == 0 {
        for j in i..BUFFER_SIZE {
            buffer[j] = 0;
        }
        //Encrypt buffer
        let ciphertext = stream_encryptor
            .encrypt_last(buffer.as_slice())
            .map_err(|err| anyhow!("Failed to encrypt buffer: {err}"))?;
        //Write encrypted buffer
        let write_count = server_stream
            .write(ciphertext.as_slice())
            .map_err(|err| anyhow!("Could not write to server: {err}"))?;
        return Ok(());
    }

    //Find all the file lengths, and write the offset each file can be found at, then pad the
    //buffer, then send the file contents. First file starts immediately, the beginning of the nth file is
    //listed by the n-1th offset entry.
    let mut length_so_far = 0u64;
    for filename in &filenames {
        //Open file and get length
        let file = fs::File::open(filename)
            .map_err(|err| anyhow!("Could not open file {}: {}", filename, err))?;

        //Prepend file length
        let file_length = file
            .metadata()
            .map_err(|err| anyhow!("Could not read length of file {}: {}", filename, err))?
            .len() as u64;

        for byte in length_so_far.to_be_bytes() {
            buffer[i] = byte;
            i += 1;
            if i >= BUFFER_SIZE {
                encrypt_and_write(&buffer, &mut server_stream, &mut stream_encryptor)?;
                i = 0;
            }
        }
        length_so_far += file_length;
    }
    //Pad end of buffer with 0s and flush it
    if i != 0 {
        for j in i..BUFFER_SIZE {
            buffer[j] = 0;
        }
        //Encrypt buffer
        let ciphertext = stream_encryptor
            .encrypt_next(buffer.as_slice())
            .map_err(|err| anyhow!("Failed to encrypt buffer: {err}"))?;

        //Write encrypted buffer
        let write_count = server_stream
            .write(ciphertext.as_slice())
            .map_err(|err| anyhow!("Could not write to server: {err}"))?;
    }
    for filename in filenames {
        //Open file
        let mut file = fs::File::open(filename)
            .map_err(|err| anyhow!("Could not open file {}: {}", filename, err))?;
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
        //Fill the rest of the buffer with 0s and flush it
        for j in i..BUFFER_SIZE {
            buffer[j] = 0;
        }
    }
    //Encrypt buffer
    let ciphertext = stream_encryptor
        .encrypt_last(buffer.as_slice())
        .map_err(|err| anyhow!("Failed to encrypt buffer: {err}"))?;
    //Write encrypted buffer
    let write_count = server_stream
        .write(ciphertext.as_slice())
        .map_err(|err| anyhow!("Could not write to server: {err}"))?;

    Ok(())
}

pub fn add_user(stream: ServerUserAlterStream, user: (String, RsaPublicKey)) -> Result<u32> {

    let mut stream = stream.stream;

    //Write intention to add or remove
    let buf = [ADD];
    let write_count = stream.write(&[ADD])
        .map_err(|err| anyhow!("Could not write intent to add or remove client {} to server: {err}", user.0))?;
    if write_count != 1 {
        bail!("Could not write intent to add or remove client {} to server, tried to write 1 byte, actually wrote {write_count} bytes", user.0);
    }

    //Receive authentication code for client
    let mut code_buf = [0u8; 4];
    let read_count = stream.read(&mut code_buf)
        .map_err(|err| anyhow!("Error reading authentication code to pass to new user from server: {err}"))?;
    if read_count != 4 {
        bail!("Error reading authentication code to pass to new user from server: Tried to read 4 bytes, actually read {read_count} bytes");
    }
    Ok(u32::from_be_bytes(code_buf))
}
pub fn remove_user(stream: ServerUserAlterStream, user: (String, RsaPublicKey)) -> Result<()> {

    let mut stream = stream.stream;

    //Write intention to add or remove
    let write_count = stream.write(&[REMOVE])
        .map_err(|err| anyhow!("Could not write intent to add or remove client {} to server: {err}", user.0))?;
    if write_count != 1 {
        bail!("Could not write intent to add or remove client {} to server, tried to write 1 byte, actually wrote {write_count} bytes", user.0);
    }

    //Write public key
    let ser_key = user.1.to_public_key_der()
        .map_err(|err| anyhow!("Failed serialising public key to send to server to authenticate: {err}"))?;
    let ser_key = ser_key.as_bytes();

    let write_count = stream.write(&ser_key)
        .map_err(|err| anyhow!("Could not write public key to server to alter client list: {err}"))?;
    if write_count != PUB_KEY_SER_LEN {
        bail!("Failed to write public key to server to alter client list. Tried to write {PUB_KEY_SER_LEN} bytes, actually wrote {write_count} bytes");
    }
    
    //Write username
    let username = user.0.as_bytes();
    let len = username.len();
    let write_count = stream.write(&(len as u64).to_be_bytes())
        .map_err(|err| anyhow!("Could not write username length to server to alter client list: {err}"))?;
    if write_count != 8 {
        bail!("Failed to write username length to server to alter client list. Tried to write 8 bytes, actually wrote {write_count} bytes");
    }
    let write_count = stream.write(&username)
        .map_err(|err| anyhow!("Could not write username to server to alter client list: {err}"))?;
    if write_count != len {
        bail!("Failed to write username to server to alter client list. Tried to write {len} bytes, actually wrote {write_count} bytes");
    }
    Ok(())
}
