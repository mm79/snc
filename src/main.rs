use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Error as AeadError, Key, KeyInit, Nonce};
use atty::Stream;
use clap::{Parser, Subcommand};
use hex::decode;
use rand::rngs::OsRng;
use rand::RngCore;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    ///  openssl rand -hex 32
    #[arg(short = 'k', long)]
    key: String,
}

#[derive(Subcommand)]
enum Commands {
    Listen {
        /// tcp port
        #[arg(short, long)]
        port: u16,
    },

    Connect {
        #[arg(short = 'H', long)]
        host: String,

        /// tcp port
        #[arg(short, long)]
        port: u16,
    },
}

fn create_cipher_from_hex_32(hex: &str) -> Result<Aes256Gcm, String> {
    let bytes = decode(hex).map_err(|e| format!("Invalid hex key: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Key must be 32 bytes (usage: openssl; got {} bytes",
            bytes.len()
        ));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    let key = Key::<Aes256Gcm>::from_slice(&k);
    Ok(Aes256Gcm::new(key))
}

async fn send_encrypted(
    write: &mut (impl AsyncWriteExt + Unpin + ?Sized),
    cipher: &Aes256Gcm,
    plaintext: &[u8],
) -> io::Result<()> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // ciphertext includes 16-byte GCM tag at the end
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;

    // Total length: nonce (12 bytes) + ciphertext (includes tag)
    let payload_len = (12 + ciphertext.len()) as u32;
    write.write_all(&payload_len.to_be_bytes()).await?;
    write.write_all(&nonce_bytes).await?;
    write.write_all(&ciphertext).await?;

    Ok(())
}

async fn recv_encrypted(
    read: &mut (impl AsyncReadExt + Unpin + ?Sized),
    cipher: &Aes256Gcm,
) -> io::Result<Vec<u8>> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const MIN_PAYLOAD_SIZE: usize = NONCE_SIZE + TAG_SIZE;

    // Read the 4-byte prefix
    let mut len_bytes = [0u8; 4];
    if read.read_exact(&mut len_bytes).await? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Failed to read length prefix",
        ));
    }
    let payload_len = u32::from_be_bytes(len_bytes) as usize;

    // Validation
    if payload_len < MIN_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Payload length ({}) is too small; expected at least {} bytes (Nonce + Tag)",
                payload_len, MIN_PAYLOAD_SIZE
            ),
        ));
    }

    // Read the Nonce bytes
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    read.read_exact(&mut nonce_bytes).await?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read the Ciphertext + Tag
    let ciphertext_len = payload_len - NONCE_SIZE;
    let mut ciphertext = vec![0u8; ciphertext_len];
    read.read_exact(&mut ciphertext).await?;

    // Decrypt the data and verify the tag
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e: AeadError| {
            eprintln!("Decryption failed: {:?}", e);
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Decryption and tag verification failed",
            )
        })
}

async fn handle_connection(stream: TcpStream, peer: SocketAddr, cipher: Arc<Aes256Gcm>) {
    println!("[{}] connected", peer);

    let (read_half, write_half) = stream.into_split();
    let write_shared = Arc::new(Mutex::new(write_half));
    let cipher_r = Arc::clone(&cipher);
    let cipher_w = Arc::clone(&cipher);
    let write_for_writer = Arc::clone(&write_shared);

    let mut reader_handle: JoinHandle<()> = tokio::spawn(async move {
        let mut r = BufReader::new(read_half);
        loop {
            match recv_encrypted(&mut r, &cipher_r).await {
                Ok(plaintext) => {
                    if plaintext.is_empty() {
                        // skip
                        continue;
                    }
                    if io::stdout().write_all(&plaintext).await.is_err() {
                        break;
                    }
                    let _ = io::stdout().flush().await;
                }
                Err(_) => break,
            }
        }
        println!("[{}] reader exiting", peer);
    });

    let mut writer_handle: JoinHandle<()> = tokio::spawn(async move {
        let stdin = io::stdin();
        let is_tty = atty::is(Stream::Stdin);

        if !is_tty {
            let mut all = Vec::new();
            let mut r = BufReader::new(stdin);
            if let Err(e) = r.read_to_end(&mut all).await {
                eprintln!("[writer:{}] stdin read error: {:?}", peer, e);
                return;
            }
            if all.is_empty() {
                return;
            }
            let mut guard = write_for_writer.lock().await;
            if let Err(e) = send_encrypted(&mut *guard, &cipher_w, &all).await {
                eprintln!("[writer:{}] send error: {:?}", peer, e);
            }

            return;
        }

        // is_tty
        let mut r = BufReader::new(stdin);
        let mut buf = [0u8; 1024];
        loop {
            let n = match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[writer:{}] stdin read error: {:?}", peer, e);
                    break;
                }
            };
            let mut guard = write_for_writer.lock().await;
            if let Err(e) = send_encrypted(&mut *guard, &cipher_w, &buf[..n]).await {
                eprintln!("[writer:{}] send error: {:?}", peer, e);
                break;
            }
        }
        println!("[{}] writer exiting", peer);
    });

    tokio::select! {
        _ = &mut reader_handle => {
            writer_handle.abort();
        }
        _ = &mut writer_handle => {
            reader_handle.abort();
        }
    }

    println!("[{}] connection closed", peer);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cipher = Arc::new(create_cipher_from_hex_32(&cli.key)?);

    match cli.command {
        Commands::Listen { port } => {
            let addr = format!("0.0.0.0:{}", port);
            let listener = TcpListener::bind(&addr).await?;
            println!("[*] Listening on {}", addr);

            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let c = Arc::clone(&cipher);
                        tokio::spawn(async move {
                            handle_connection(stream, peer, c).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("[accept error] {:?}", e);
                    }
                }
            }
        }

        Commands::Connect { host, port } => {
            let addr = format!("{}:{}", host, port);
            let stream = TcpStream::connect(&addr).await?;
            let peer = stream.peer_addr().unwrap();

            handle_connection(stream, peer, cipher).await;
            Ok(())
        }
    }
}
