use crate::*;
//Returns Ok(None) if the message is not for you. Returns the key and nonce otherwise. Returns
//Error when the connection to server fails or the data is malformed.
pub fn determine_recipiency(mut client_stream: TcpStream, priv_key: &RsaPrivateKey) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut key_num_bytes = [0u8; 8];
    let read_count = client_stream.read(&mut key_num_bytes)
        .map_err(|err| anyhow!("Failed to read number of keys to determine recipiency: {err}"))?;
    if read_count < 8 {
        bail!("Failed to read number of keys to determine recipiency: Too few bytes transmitted");
    }
    let key_num = u64::from_be_bytes(key_num_bytes);

    let mut key_buf = [0u8; ENCRYPTED_KEY_LEN];
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut key_buf_pos = 0;
    let mut buf_pos = BUFFER_SIZE;
    let mut keys_seen = 0;
    while keys_seen < key_num {
        if buf_pos == BUFFER_SIZE {
            let read_count = client_stream.read(&mut buffer)
                .map_err(|err| anyhow!("Failed to read number of keys to determine recipiency: {err}"))?;
        if read_count < 8 {
            bail!("Failed to read number of keys to determine recipiency: Too few bytes transmitted");
        }
            buf_pos = 0;
        }
        key_buf[key_buf_pos] = buffer[buf_pos];
        key_buf_pos += 1;
        buf_pos += 1;
        if key_buf_pos == ENCRYPTED_KEY_LEN {
            key_buf_pos = 0;
            keys_seen += 1;
            let (magic, key, nonce) = decrypt_key(key_buf, priv_key)?;
            if magic.len() != MAG_CONSTANT.len() {
                bail!("Length of magic constant is not what it should be. Was {}, should be {}", magic.len(), MAG_CONSTANT.len());
            }
            if key.len() != KEY_LEN {
                bail!("Length of key is not what it should be. Was {}, should be {}", key.len(), KEY_LEN);
            }
            if nonce.len() != NONCE_LEN {
                bail!("Length of nonce is not what it should be. Was {}, should be {}", nonce.len(), NONCE_LEN);
            }
            if magic != MAG_CONSTANT {
                continue;
            }
            return Ok(Some((key, nonce)));
        }
    }
    Ok(None)
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

fn scratch_space(mut stream: TcpStream, priv_key: RsaPrivateKey) -> Result<bool> {
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
    let mut buffer = [0u8; BUFFER_SIZE];
    'read: loop {
        if buf_pos == BUFFER_SIZE {
            read_count = stream.read(&mut buffer)
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
