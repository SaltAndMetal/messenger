use crate::*;

//Returns Ok(Ok(Some(timestamp))) if the message is not for you, with the exact timestamp of the message. Returns Ok(Ok(None) if there is no message past that timestamp. Returns the exact timestamp of the message, the length of the key section, the key and the nonce otherwise. Returns
//Error when the connection to server fails or the data is malformed, or if the offset of the
//server stream is not 0.
pub fn determine_recipiency(
    mut server_stream: ServerKeysStream,
    timestamp: u64,
    priv_key: &RsaPrivateKey,
) -> Result<Result<(u64, u64, Vec<u8>, Vec<u8>), Option<u64>>> {
    //Tell the server the timestamp to search past
    let write_count = server_stream
        .stream
        .write(&timestamp.to_be_bytes())
        .map_err(|err| anyhow!("Failed to write timestamp to server: {err}"))?;
    if write_count < 8 {
        bail!("Failed to write timestamp to server: {write_count} bytes transmitted, expected 8");
    }
    println!("Wrote timestamp: {timestamp}");

    //Server will write back all 1s if there is a message to send back, and all 0s if there isn't.
    //Fail gracefully and return the timestamp if there is no message
    let mut confirmation_buf = [0u8; 1];
    let read_count = server_stream
        .stream
        .read(&mut confirmation_buf)
        .map_err(|err| anyhow!("Failed to read exact timestamp of message: {err}"))?;
    if read_count < 1 {
        bail!("Failed to read confirmation of existence of message: {read_count} bytes transmitted, expected 8. Buffer sent is {confirmation_buf:?}");
    }
    if u8::from_be_bytes(confirmation_buf) != 255 {
        return Ok(Err(None));
    }

    //Read the exact timestamp of the message
    let mut exact_timestamp_buf = [0u8; 8];
    let read_count = server_stream
        .stream
        .read(&mut exact_timestamp_buf)
        .map_err(|err| anyhow!("Failed to read exact timestamp of message: {err}"))?;
    if read_count < 8 {
        bail!("Failed to read exact timestamp of message: {read_count} bytes transmitted, expected 8. Buffer sent is {exact_timestamp_buf:?}");
    }
    let exact_timestamp = u64::from_be_bytes(exact_timestamp_buf);

    //Read the number of keys
    let mut key_num_bytes = [0u8; 8];
    let read_count = server_stream
        .stream
        .read(&mut key_num_bytes)
        .map_err(|err| anyhow!("Failed to read number of keys to determine recipiency: {err}"))?;
    if read_count < 8 {
        bail!("Failed to read number of keys to determine recipiency: Too few bytes transmitted. Expected 8 bytes, received {read_count} bytes");
    }
    let key_num = u64::from_be_bytes(key_num_bytes);

    let mut buffer = [0u8; ENCRYPTED_KEY_LEN];
    let mut keys_seen = 0;
    while keys_seen < key_num {
        let read_count = server_stream
            .stream
            .read(&mut buffer)
            .map_err(|err| anyhow!("Failed to read key to determine recipiency: {err}"))?;
        if read_count < ENCRYPTED_KEY_LEN {
            bail!("Failed to read key to determine recipiency: Too few bytes transmitted. Expected {ENCRYPTED_KEY_LEN} bytes, recieved {read_count} bytes");
        }
        keys_seen += 1;
        let (magic, key, nonce) = match decrypt_key(buffer, priv_key) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if magic.len() != MAG_CONSTANT.len() {
            bail!(
                "Length of magic constant is not what it should be. Was {}, should be {}",
                magic.len(),
                MAG_CONSTANT.len()
            );
        }
        if magic != MAG_CONSTANT {
            continue;
        }
        if key.len() != KEY_LEN {
            bail!(
                "Length of key is not what it should be. Was {}, should be {}",
                key.len(),
                KEY_LEN
            );
        }
        if nonce.len() != NONCE_LEN {
            bail!(
                "Length of nonce is not what it should be. Was {}, should be {}",
                nonce.len(),
                NONCE_LEN
            );
        }
        return Ok(Ok((
            exact_timestamp,
            key_num * ENCRYPTED_KEY_LEN as u64 + 8,
            key,
            nonce,
        )));
    }
    println!("h");
    Ok(Err(Some(exact_timestamp)))
}

fn decrypt_key(
    encrypted_key: [u8; ENCRYPTED_KEY_LEN],
    priv_key: &RsaPrivateKey,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let decrypted_magic_key_nonce = priv_key
        .decrypt(padding, &encrypted_key)
        .map_err(|err| anyhow!("Failed to decrypt: {err}"))?;
    if decrypted_magic_key_nonce.len() != (MAG_CONSTANT.len() + KEY_LEN + NONCE_LEN) {
        bail!(
            "Decrypted key+nonce+magic is the wrong length. Should be {}, was {}",
            MAG_CONSTANT.len() + KEY_LEN + NONCE_LEN,
            decrypted_magic_key_nonce.len()
        );
    }
    let (magic, key_nonce) = decrypted_magic_key_nonce.split_at(MAG_CONSTANT.len());
    if key_nonce.len() != (KEY_LEN + NONCE_LEN) {
        bail!(
            "Decrypted key+nonce is the wrong length. Should be {}, was {}",
            KEY_LEN + NONCE_LEN,
            decrypted_magic_key_nonce.len()
        );
    }
    let (key, nonce) = key_nonce.split_at(KEY_LEN);
    Ok((magic.into(), key.into(), nonce.into()))
}

//Receive and store the message in the local message database. We retrieve file number and length, but not the contents. File contents are downloaded on demand. The server will send encrypted data until told to stop.
pub fn recieve_message(
    mut server_stream: ServerSendStream,
    exact_timestamp: u64,
    sym_key: [u8; KEY_LEN],
    sym_nonce: [u8; NONCE_LEN],
    date_keys_path: &str,
    database_path: &str,
) -> Result<()> {
    let date_keys = fs::File::open(date_keys_path)
        .map_err(|err| anyhow!("Could not open date key file at path {date_keys_path}: {err}"))?;

    //Opens the database and date keys file for appending
    let mut database = fs::File::options()
        .append(true)
        .open(database_path)
        .map_err(|err| anyhow!("Could not open database file at path {database_path}: {err}"))?;
    let database_len = database
        .metadata()
        .map_err(|err| {
            anyhow!("Could not access metadata for database file at path {database_path}: {err}")
        })?
        .len();
    let mut date_keys = fs::File::options()
        .append(true)
        .open(date_keys_path)
        .map_err(|err| anyhow!("Could not open data key file at path {date_keys_path}: {err}"))?;

    //Write the exact timestamp and index the message can be found at to the date keys file
    date_keys
        .write(&exact_timestamp.to_be_bytes())
        .map_err(|err| {
            anyhow!(
                "Could not write current time into date key file at path {date_keys_path}: {err}"
            )
        })?;
    date_keys.write(&database_len.to_be_bytes())
        .map_err(|err| anyhow!("Could not write index for message into data key file at path {date_keys_path}: {err}"))?;

    //Init symmetric crypto
    let aead = XChaCha20Poly1305::new(sym_key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, sym_nonce.as_ref().into());

    //Has to be +16 due to the authentication tag on each packet.
    let mut buffer = [0u8; BUFFER_SIZE + 16];

    //Sets up a bunch of buffers and buffer indices
    let mut plaintext_buffer: Vec<u8>;

    //Grab the message length. Stored in plaintext
    let mut message_len_buffer = [0u8; 8];
    let write_count = server_stream
        .stream
        .write(&(message_len_buffer.len() as u64).to_be_bytes())
        .map_err(|err| anyhow!("Failed to write requested byte amount to server: {err}"))?;
    if write_count < 8 {
        bail!("Could not write requested byte amount to server. Tried to send 8 bytes, actually sent {write_count} bytes");
    }
    let read_count = server_stream
        .stream
        .read(&mut message_len_buffer)
        .map_err(|err| anyhow!("Failed to read from server: {err}"))?;
    //Write message length to database
    let write_count = database.write(&message_len_buffer)
        .map_err(|err| anyhow!("Error writing message length to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    if write_count < message_len_buffer.len() {
        bail!("Could not write message length to server. Tried to send {} bytes, actually sent {write_count} bytes. The last entry in date_keys and however much message was written must be cleaned up.", message_len_buffer.len());
    }
    let message_len = u64::from_be_bytes(message_len_buffer);

    //Grab the file count. Stored in plaintext
    let mut file_count_buffer = [0u8; 8];
    let write_count = server_stream
        .stream
        .write(&(file_count_buffer.len() as u64).to_be_bytes())
        .map_err(|err| anyhow!("Failed to write requested byte amount to server: {err}"))?;
    if write_count < 8 {
        bail!("Could not write requested byte amount to server. Tried to send 8 bytes, actually sent {write_count} bytes");
    }
    let read_count = server_stream
        .stream
        .read(&mut file_count_buffer)
        .map_err(|err| anyhow!("Failed to read from server: {err}"))?;
    //Write file count to database
    let write_count = database.write(&file_count_buffer)
        .map_err(|err| anyhow!("Error writing file count to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    if write_count < file_count_buffer.len() {
        bail!("Could not write file count to server. Tried to send {} bytes, actually sent {write_count} bytes. The last entry in date_keys and however much message was written must be cleaned up.", file_count_buffer.len());
    }
    let file_count = u64::from_be_bytes(file_count_buffer);

    //Factor in the 16 bytes the encryption adds to each packet
    let actual_message_len =
        16 * ((message_len as f64 / BUFFER_SIZE as f64).ceil() as u64) + message_len;
    let packet_count = (actual_message_len as f64 / (BUFFER_SIZE + 16) as f64).ceil() as u64;

    //Read the message
    for i in 0..packet_count - 1 {
        let write_count = server_stream
            .stream
            .write(&(buffer.len() as u64).to_be_bytes())
            .map_err(|err| anyhow!("Failed to write requested byte amount to server: {err}"))?;
        if write_count < 8 {
            bail!("Could not write requested byte amount to server. Tried to send 8 bytes, actually sent {write_count} bytes");
        }

        let read_count = server_stream
            .stream
            .read(&mut buffer)
            .map_err(|err| anyhow!("Failed to read from server: {err}"))?;
        if read_count < buffer.len() {
            bail!("Could not read requested message from server. Tried to read {} bytes, actually read {read_count} bytes.", buffer.len());
        }

        plaintext_buffer = stream_decryptor
            .decrypt_next(buffer.as_slice())
            .map_err(|err| anyhow!("Failed to decrypt message: {err}"))?;

        let write_count = database.write(&plaintext_buffer)
            .map_err(|err| anyhow!("Error writing message data to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
        if write_count < plaintext_buffer.len() {
            bail!("Could not write message to database. Tried to write {} bytes, actually wrote {write_count} bytes. The last entry in date_keys and however much message was written must be cleaned up.", plaintext_buffer.len());
        }
    }
    //Handles the last message chunk. Unfortunate to duplicate code like this, but this seems to be the
    //most ergonomic way
    let write_count = server_stream
        .stream
        .write(&(buffer.len() as u64).to_be_bytes())
        .map_err(|err| anyhow!("Failed to write requested byte amount to server: {err}"))?;
    if write_count < 8 {
        bail!("Could not write requested byte amount to server. Tried to send 8 bytes, actually sent {write_count} bytes");
    }
    let read_count = server_stream
        .stream
        .read(&mut buffer)
        .map_err(|err| anyhow!("Failed to read from server: {err}"))?;
    if read_count < buffer.len() {
        bail!("Could not read requested message from server. Tried to read {} bytes, actually read {read_count} bytes", buffer.len());
    }

    plaintext_buffer = stream_decryptor
        .decrypt_last(buffer.as_slice())
        .map_err(|err| anyhow!("Failed to decrypt message: {err}"))?;
    let mut remainder_len = message_len as usize % BUFFER_SIZE;
    if remainder_len == 0 {
        remainder_len = BUFFER_SIZE;
    }
    let write_count = database.write(&plaintext_buffer[..remainder_len])
        .map_err(|err| anyhow!("Error writing message data to database: {err}. The last entry in date_keys and however much message was written must be cleaned up."))?;
    if write_count < remainder_len {
        bail!("Could not write message to database. Tried to write {} bytes, actually wrote {write_count} bytes. The last entry in date_keys and however much message was written must be cleaned up.", plaintext_buffer.len());
    }

    //Tell the server we are done
    let write_count = server_stream
        .stream
        .write([0u8; 8].as_slice())
        .map_err(|err| anyhow!("Failed to write 0 requested bytes to server: {err}"))?;
    if write_count < 8 {
        bail!("Could not write 0 requested bytes to server. Tried to send 8 bytes, actually sent {write_count} bytes");
    }
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
    let mut date_keys = fs::File::open(date_key_path)
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
    let mut low = 0;
    let mut high = date_keys_len - 1;
    let index;
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
                break;
            }
            //If less, check if the next one is more. If it is, that is the one. Otherwise, keep
            //looking
            Ordering::Less => {
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

//Grabs messages from the local message database by exact timestamp. The return type is (message,
//author, authentication_status, file offsets)
pub fn pull_local_messages_date(
    timestamp: u64,
    date_keys_path: &str,
    database_path: &str,
    user_key_map: &BiHashMap<String, RsaPublicKey>,
) -> Result<(String, String, bool, Vec<u64>)> {
    //Get index
    let index_timestamp = locate_index_from_timestamp(timestamp, date_keys_path, true)?;
    if index_timestamp.is_none() {
        bail!("No message with specified timestamp {timestamp} exists");
    }
    let (index, _) = index_timestamp.unwrap();

    //Open database file at index
    let mut database = fs::File::open(database_path)
        .map_err(|err| anyhow!("Could not open database file to read local message: {err}"))?;
    database.seek(SeekFrom::Start(index)).map_err(|err| {
        anyhow!("Could not seek to index {index} in database file to read local message: {err}")
    })?;

    //Read message length
    let mut len_buf = [0u8; 8];
    let read_count = database
        .read(&mut len_buf)
        .map_err(|err| anyhow!("Could not read message length from local database"))?;
    if read_count < len_buf.len() {
        bail!("Could not read message length from local database. Too few bytes read. Tried to read {} bytes, read {read_count} instead", len_buf.len());
    }
    let message_len = u64::from_be_bytes(len_buf);

    //Read file count
    let mut count_buf = [0u8; 8];
    let read_count = database
        .read(&mut count_buf)
        .map_err(|err| anyhow!("Could not read file count from local database"))?;
    if read_count < count_buf.len() {
        bail!("Could not read file count from local database. Too few bytes read. Tried to read {} bytes, read {read_count} instead", count_buf.len());
    }
    let file_count = u64::from_be_bytes(count_buf);

    //Read message contents
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut message = Vec::with_capacity(message_len as usize);
    let packet_count = (message_len as f64 / BUFFER_SIZE as f64).ceil() as u64;
    for _ in 0..packet_count - 1 {
        let read_count = database
            .read(&mut buffer)
            .map_err(|err| anyhow!("Could not read message from local database"))?;
        if read_count < buffer.len() {
            bail!("Could not read message from local database. Too few bytes read. Tried to read {} bytes, read {read_count} instead", buffer.len());
        }
        message.append(&mut buffer.to_vec());
    }
    //Read remainder of message
    let read_count = database
        .read(&mut buffer[..message_len as usize % BUFFER_SIZE])
        .map_err(|err| anyhow!("Could not read message from local database"))?;
    if read_count < message_len as usize % BUFFER_SIZE {
        bail!("Could not read message from local database. Too few bytes read. Tried to read {} bytes, read {read_count} instead", buffer.len());
    }
    message.append(&mut buffer[..message_len as usize % BUFFER_SIZE].to_vec());

    let mut file_offsets: Vec<u64> = Vec::with_capacity(file_count as usize);
    for i in 0..file_count {
        file_offsets.push(u64::from_be_bytes(
            <&[u8] as TryInto<[u8; 8]>>::try_into(
                &message[(message_len - file_count * 8 + i * 8) as usize
                    ..(message_len - file_count * 8 + (i + 1) * 8) as usize],
            )
            .unwrap(),
        ));
    }

    let mut username_len_bytes = [0u8; 8];
    for (i, byte) in message[..8].iter().enumerate() {
        username_len_bytes[i] = *byte;
    }
    let username_len = u64::from_be_bytes(username_len_bytes) as usize;
    if username_len > USERNAME_MAX_LEN {
        bail!(
            "Username too long. Max length is {USERNAME_MAX_LEN}, actual length was {username_len}"
        );
    }
    let mut username_bytes = Vec::with_capacity(username_len);
    for i in 0..username_len {
        username_bytes.push(message[i + 8]);
    }
    let username =
        String::from_utf8(username_bytes).map_err(|err| anyhow!("Username not valid utf8: err"))?;
    let public_key = user_key_map
        .get_by_left(&username)
        .ok_or(())
        .map_err(|_| anyhow!("Username {username} not recognized"))?;
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key.clone());
    let mut signature_bytes = Vec::with_capacity(SIGNATURE_LEN);
    for i in 0..SIGNATURE_LEN {
        signature_bytes.push(message[i + 8 + username_len]);
    }
    let signature: rsa::pss::Signature = signature_bytes.into();
    let mut auth = false;
    if let Ok(_) = verifying_key.verify(&message[8 + username_len + SIGNATURE_LEN..], &signature) {
        auth = true;
    }
    Ok((
        String::from_utf8(message[8 + username_len + SIGNATURE_LEN..].into())
            .map_err(|err| anyhow!("Failed to convert message data to string: {err}"))?,
        username,
        auth,
        file_offsets,
    ))
}
