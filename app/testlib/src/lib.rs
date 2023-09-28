extern crate clientlib;
extern crate serverlib;
extern crate rsa;
extern crate rand;
extern crate bimap;
extern crate anyhow;
#[cfg(test)]
mod tests {

    use std::net::SocketAddr;
    use anyhow::anyhow;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{DecodePublicKey, DecodePrivateKey}};
    use std::thread;
    use std::fs::File;
    use std::io::Read;
    use std::thread::sleep;
    use std::time::Duration;
    use std::sync::{Arc, Mutex, mpsc};
    use std::sync::mpsc::{Sender, Receiver};
    use bimap::BiHashMap;
    use serverlib::*;

    //Tests:
    //Client sending a message
    //Server recieving and storing a message
    //Server fetching a message for client
    //Client fetching a message
    //If this test fails, and it looks like the client panicked, it is possible the server panicked
    //but it wasn't picked up because it was in a different thread, and the client was the victim
    fn short_message_send_recv(create_files: bool, server_address: &SocketAddr, admin_priv_key: &RsaPrivateKey, admin_pub_key: &RsaPublicKey) {
        let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        message_send_recv(message, create_files, server_address, admin_priv_key, admin_pub_key)
    }
    fn long_message_send_recv(create_files: bool, server_address: &SocketAddr, admin_priv_key: &RsaPrivateKey, admin_pub_key: &RsaPublicKey) {
        let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. In ante metus dictum at tempor commodo ullamcorper a. Lacus vestibulum sed arcu non. Lectus quam id leo in vitae turpis massa sed elementum. Molestie at elementum eu facilisis sed odio. Feugiat in fermentum posuere urna. Diam sit amet nisl suscipit adipiscing. Eu mi bibendum neque egestas congue. Neque aliquam vestibulum morbi blandit cursus risus at ultrices mi. Laoreet non curabitur gravida arcu ac tortor dignissim convallis. Donec ultrices tincidunt arcu non sodales neque sodales. Purus gravida quis blandit turpis. Nisi quis eleifend quam adipiscing vitae proin sagittis nisl rhoncus. Facilisis leo vel fringilla est ullamcorper. Ut porttitor leo a diam sollicitudin tempor. Facilisis magna etiam tempor orci eu lobortis elementum nibh. Fermentum dui faucibus in ornare quam viverra. Nisl suscipit adipiscing bibendum est ultricies integer. Bibendum at varius vel pharetra vel turpis. Ut diam quam nulla porttitor. Nec feugiat nisl pretium fusce id. At in tellus integer feugiat scelerisque varius morbi. Tellus mauris a diam maecenas sed enim ut. Bibendum est ultricies integer quis auctor elit sed vulputate mi. Sit amet mauris commodo quis imperdiet massa tincidunt nunc pulvinar.";
        message_send_recv(message, create_files, server_address, &admin_priv_key, admin_pub_key)
    }
    fn message_send_recv(message: &str, create_files: bool, server_address: &SocketAddr, admin_priv_key: &RsaPrivateKey, admin_pub_key: &RsaPublicKey) {

        let database_path = "/tmp/server_database";
        let date_key_path = "/tmp/server_date_keys";
        let usernames_and_keys_path = "/tmp/users";
        //Create database files
        if create_files {
            File::create(date_key_path).unwrap();
            File::create(database_path).unwrap();
            File::create("/tmp/client_date_keys").unwrap();
            File::create("/tmp/client_database").unwrap();
            File::create(usernames_and_keys_path).unwrap();
        }

        //Create channels
        let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        let (tx2, rx2): (Sender<()>, Receiver<()>) = mpsc::channel();

        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let priv_key2 = RsaPrivateKey::new(&mut rng, 4096).unwrap();
        let pub_key2 = RsaPublicKey::from(&priv_key2);
        let username = "client";
        let mut user_key_map = BiHashMap::new();
        user_key_map.insert(String::from(username), pub_key.clone());
        //println!("Added users1");
        //let server_auth = clientlib::ServerUserAlterStream::init_server(server_address, admin_priv_key, admin_pub_key).unwrap();
        //println!("Added users2");
        //clientlib::alter_users(server_auth, true, (username.to_string(), pub_key.clone())).unwrap();
        //println!("Added users");

        //Start server
        let user_key_map = user_key_map.clone();
        thread::scope(|s| {
            let server;
            {
                let user_key_map = user_key_map.clone();
        server = s.spawn(move || {
            let listener = std::net::TcpListener::bind(server_address).unwrap();
            listener.set_nonblocking(true).expect("Cannot set non-blocking");
            let file_access = Arc::new(Mutex::new(serverlib::FileAccess::Nothing));
            let user_file_access = Arc::new(Mutex::new(()));
            let usernames_and_keys = Arc::new(Mutex::new((user_key_map, Vec::new())));
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
                                date_key_path,
                                database_path,
                                file_access_clone,
                                user_file_access_clone,
                                usernames_and_keys,
                                usernames_and_keys_path,
                            )
                            .map_err(|err| anyhow!("server error: {err}")).unwrap();
                        });
                    }
                    Err(_) => (),
                }
                if rx.try_recv().is_ok() {
                    drop(listener);
                    tx2.send(()).unwrap();
                    break;
                }
                sleep(Duration::from_millis(10))
            }
        });
            }

        //Send message. Loop until the server is online
        let mut server_representation = clientlib::ServerRecieveStream::init_server(server_address, &priv_key, &pub_key);
        let mut i = 0;
        while server_representation.is_err() {
            sleep(Duration::from_millis(1));
            server_representation = clientlib::ServerRecieveStream::init_server(server_address, &priv_key, &pub_key);
            if i > 5000 {
                panic!("Server took too long to initialise")
            }
            i += 1;
        }
        //Guarantees a timestamp earlier than the sent message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64 - 1;
        println!("Saved timestamp {timestamp}");

        sleep(Duration::from_secs(1));
        let server_representation = server_representation.unwrap();
        clientlib::symmetric_encrypt_and_send(message.as_bytes(), Vec::new(), server_representation, vec![&pub_key2, &pub_key], &priv_key, "client").unwrap();

        //Let server finish writing
        sleep(Duration::from_secs(1));

        //Determine recipiency
        let server_representation = clientlib::ServerKeysStream::init_server(server_address, &priv_key, &pub_key).unwrap();
        let (exact_timestamp, offset, key, nonce) = clientlib::determine_recipiency(server_representation, timestamp, &priv_key).unwrap().unwrap();

        let mut key_array = [0u8; 32];
        for (i, byte) in key.iter().enumerate() {
            key_array[i] = *byte;
        }
        let mut nonce_array = [0u8; 19];
        for (i, byte) in nonce.iter().enumerate() {
            nonce_array[i] = *byte;
        }

        //Ensure no other messages
        let server_representation = clientlib::ServerKeysStream::init_server(server_address, &priv_key, &pub_key).unwrap();
        let recip_result = clientlib::determine_recipiency(server_representation, exact_timestamp+1, &priv_key).unwrap();
        assert!(recip_result.is_err());
        assert!(recip_result.unwrap_err().is_none());

        //Pull message contents
        let server_representation = clientlib::ServerSendStream::init_server(server_address, offset, exact_timestamp, &priv_key, &pub_key).unwrap();
        clientlib::recieve_message(server_representation, exact_timestamp, key_array, nonce_array, "/tmp/client_date_keys", "/tmp/client_database").unwrap();

        let message_read = clientlib::pull_local_messages_date(exact_timestamp, "/tmp/client_date_keys", "/tmp/client_database", &user_key_map).unwrap();
        if message_read.0 != message {
            panic!("Message was corrupted. Should have been:\n\"{message}\"\nwas:\n\"{}\"", message_read.0);
        }
        if !message_read.2 {
            panic!("Message {} was not authorised", message_read.0);
        }

        //If it has finished, it has panicked
        if server.is_finished() {
            panic!("Server panicked")
        }
        //Tell the server to stop
        tx.send(()).unwrap();
        //Wait for the server to stop
        rx2.recv().unwrap();
        //Make sure the timestamp is different
        sleep(Duration::from_secs(1));
        });
    }
    //Each client concurrently sends messages to the next 2 clients. Then they all read their
    //messages.
    fn multiple_send_recv_test(keys: &[(RsaPublicKey, RsaPrivateKey)], thread_count: usize, server_address: &SocketAddr, admin_priv_key: &RsaPrivateKey, admin_pub_key: &RsaPublicKey) {

        let database_path = "/tmp/server_database";
        let date_key_path = "/tmp/server_date_keys";
        let usernames_and_keys_path = "/tmp/users";
        //Create database files
        File::create(date_key_path).unwrap();
        File::create(database_path).unwrap();
        File::create(usernames_and_keys_path).unwrap();

        //Create channels
        let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        let (tx2, rx2): (Sender<()>, Receiver<()>) = mpsc::channel();

        let mut user_key_map: BiHashMap<String, RsaPublicKey> = BiHashMap::new();
        for i in 0..thread_count {
            user_key_map.insert(format!("client number {i}"), keys[i].0.clone());
        }

        //Start server
        let server;
        {
        let user_key_map = user_key_map.clone();
        let server_address = server_address.clone();
        server = thread::spawn(move || {
            let listener = std::net::TcpListener::bind(server_address).unwrap();
            listener.set_nonblocking(true).expect("Cannot set non-blocking");
            let file_access = Arc::new(Mutex::new(serverlib::FileAccess::Nothing));
            let user_file_access = Arc::new(Mutex::new(()));
            let usernames_and_keys = Arc::new(Mutex::new((user_key_map, Vec::new())));
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
                                date_key_path,
                                database_path,
                                file_access_clone,
                                user_file_access_clone,
                                usernames_and_keys,
                                usernames_and_keys_path,
                            )
                            .map_err(|err| {println!("server error: {err}")}).unwrap();
                        });
                    }
                    Err(_) => (),
                }
                if rx.try_recv().is_ok() {
                    drop(listener);
                    tx2.send(()).unwrap();
                    break;
                }
                sleep(Duration::from_millis(10));
            }
        });
        }
        
        thread::scope(|s| {
            let keys = &keys;
            let user_key_map = &user_key_map;
            for client_num in 0..thread_count {
                s.spawn(move || {
                    let client_num = client_num.clone();
                    let message = format!("Greetings from client number {client_num}");
                    //Send message. Loop until the server is online
                    let mut server_representation = clientlib::ServerRecieveStream::init_server(&server_address, &keys[client_num].1, &keys[client_num].0);
                    let mut i = 0;
                    println!("1");
                    while server_representation.is_err() {
                        println!("{:?}", server_representation.err().unwrap());
                        sleep(Duration::from_millis(1));
                        server_representation = clientlib::ServerRecieveStream::init_server(&server_address, &keys[client_num].1,  &keys[client_num].0);
                        if i > 5000 {
                            panic!("Server took too long to initialise")
                        }
                        i += 1;
                    }
                    println!("2");
                    let server_representation = server_representation.unwrap();
                    clientlib::symmetric_encrypt_and_send(message.as_bytes(), Vec::new(), server_representation, vec![&keys[client_num].0, &keys[(client_num+1)%thread_count].0, &keys[(client_num+2)%thread_count].0], &keys[client_num].1, user_key_map.get_by_right(&keys[client_num].0).unwrap()).unwrap();
                    println!("Wrote {message}. I am thread {client_num}");
                });
            }
        });
        std::thread::sleep(std::time::Duration::from_secs(2));
        thread::scope(|s| {
            let keys = &keys;
            let user_key_map = &user_key_map;
            for client_num in 0..thread_count {
                s.spawn(move || {
                    let date_key_path = format!("/tmp/client_date_keys{client_num}");
                    let database_path = format!("/tmp/client_database{client_num}");
                    File::create(&date_key_path).unwrap();
                    File::create(&database_path).unwrap();
                    //Determine recipiency of all messages
                    let correct_messages = [format!("Greetings from client number {}", client_num), format!("Greetings from client number {}", (client_num+2*thread_count-1)%thread_count), format!("Greetings from client number {}", (client_num+2*thread_count-2)%thread_count)];
                    let mut used = [false; 3];
                    let mut timestamp = 0;
                    let mut message_keys = Vec::with_capacity(3);
                    for _ in 0..thread_count {
                        let server_representation = clientlib::ServerKeysStream::init_server(&server_address, &keys[client_num].1, &keys[client_num].0)
                            .expect(&format!("I am thread {client_num}"));
                        let recip_data = clientlib::determine_recipiency(server_representation, timestamp, &keys[client_num].1)
                            .expect(&format!("I am thread {client_num}"));
                        match recip_data {
                            Ok((exact_timestamp, offset, key, nonce)) => {
                                timestamp = exact_timestamp;
                                message_keys.push((offset, key, nonce, exact_timestamp));
                            },
                            Err(Some(exact_timestamp)) => {
                                timestamp = exact_timestamp
                            },
                            Err(None) => {
                                break},
                        }
                    }
                    let mut messages = Vec::new();
            
                    for message_key in &message_keys {
                        let mut key_array = [0u8; 32];
                        for (i, byte) in message_key.1.iter().enumerate() {
                            key_array[i] = *byte;
                        }
                        let mut nonce_array = [0u8; 19];
                        for (i, byte) in message_key.2.iter().enumerate() {
                            nonce_array[i] = *byte;
                        }
                        //Pull message contents
                        let server_representation = clientlib::ServerSendStream::init_server(&server_address, message_key.0, message_key.3, &keys[client_num].1, &keys[client_num].0)
                            .expect(&format!("I am thread {client_num}"));
                        clientlib::recieve_message(server_representation, message_key.3, key_array, nonce_array, &date_key_path, &database_path)
                            .expect(&format!("I am thread {client_num}"));
    
                        let message_read = clientlib::pull_local_messages_date(message_key.3, &date_key_path, &database_path, &user_key_map)
                            .expect(&format!("I am thread {client_num}"));
                        messages.push(message_read.clone());
                        let mut panic = true;
                        for (j, message) in correct_messages.iter().enumerate() {
                            if message == &message_read.0 && !used[j] {
                                used[j] = true;
                                panic = false;
                            }
                        }
                        if panic {
                            panic!("Message {} is incorrect. Correct messages were {correct_messages:?}. I am thread {client_num}", message_read.0);
                        }
                        if !message_read.2 {
                            panic!("Message {} is unauthorised", message_read.0);
                        }
                    }
                    if message_keys.len() != std::cmp::min(3, thread_count) {
                        panic!("Incorrect message number. Expected {}, got {}. Correct messages were {correct_messages:?}. Received messages+metadata were {messages:?}. I am thread {client_num}", std::cmp::min(3, thread_count), message_keys.len());
                    }
                });
            } 
        });

        //If it has finished, it has panicked
        if server.is_finished() {
            panic!("Server panicked")
        }
        //Tell the server to stop
        tx.send(()).unwrap();
        //Wait for the server to stop
        rx2.recv().unwrap();
        //Make sure the timestamp is different
        sleep(Duration::from_secs(1));
    }
    #[test]
    fn all_test() {
        let server_address: SocketAddr = "127.0.0.1:2001".parse().expect("Server address invalid");
        let mut priv_key_file = File::open("/home/max/School/SDD/messenger/app/serverapp/rsakey.pem").unwrap();
        let mut priv_key_string = String::new();
        priv_key_file.read_to_string(&mut priv_key_string).unwrap();
        let mut pub_key_file = File::open("/home/max/School/SDD/messenger/app/serverapp/rsapubkey.pem").unwrap();
        let mut pub_key_string = String::new();
        pub_key_file.read_to_string(&mut pub_key_string).unwrap();
        let admin_priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_string).unwrap();
        let admin_pub_key = RsaPublicKey::from_public_key_pem(&pub_key_string).unwrap();
        //short_message_send_recv(true, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("1");
        //long_message_send_recv(true, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("2");
        //short_message_send_recv(false, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("3");
        //short_message_send_recv(true, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("4");
        //long_message_send_recv(false, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("5");
        //short_message_send_recv(false, &server_address, &admin_priv_key, &admin_pub_key);
        //println!("6");
        //return;
        let thread_count = 20;
        let repeats = 5;
        let mut keys = Vec::with_capacity(thread_count);
        let mut rng = rand::thread_rng();
        for i in 0..thread_count {
            println!("key num {i}");
            let priv_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
            let pub_key = RsaPublicKey::from(&priv_key);
            keys.push((pub_key, priv_key));
        }
        for i in 1..=thread_count {
            for _ in 0..repeats {
                multiple_send_recv_test(&keys[..i], i, &server_address, &admin_priv_key, &admin_pub_key);
            }
        }
    }
}
