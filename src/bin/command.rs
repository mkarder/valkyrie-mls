use anyhow::{Error, Result};
use tokio::{net::UdpSocket, select};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mlsctl", version, about = "Control your MLS network")]
pub struct Cli {
    #[arg(short, long, help = "Destination IP:port (e.g. 10.10.0.2:8000)")]
    ip: String,

    #[command(subcommand)]
    command: MlsCliCommand,
}

const IP_PREFIX: &str = "192.168.12";


#[derive(Subcommand)]
pub enum MlsCliCommand {
    Add {
        #[arg(short, long, help = "Path to KeyPackage file")]
        file: String,
    },
    Remove {
        #[arg(short, long, help = "Leaf index to remove")]
        index: u32,
    },
    Update,
    RetrieveRatchetTree,
    AddPending,
    ApplicationMsg {
        #[arg(short, long, help = "Message payload")]
        data: String,
    },
    BroadcastKeyPackage,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsOperation {
    Add = 0x00,
    AddPending = 0x01,
    Remove = 0x02,
    Update = 0x03,
    RetrieveRatchetTree = 0x04,
    ApplicationMsg = 0x05,
    BroadcastKeyPackage = 0x06,
}

impl TryFrom<u8> for MlsOperation {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(MlsOperation::Add),
            0x01 => Ok(MlsOperation::AddPending),
            0x02 => Ok(MlsOperation::Remove),
            0x03 => Ok(MlsOperation::Update),
            0x04 => Ok(MlsOperation::RetrieveRatchetTree),
            0x05 => Ok(MlsOperation::ApplicationMsg),
            0x06 => Ok(MlsOperation::BroadcastKeyPackage),
            _ => Err(Error::msg("Invalid MlsOperation byte")),
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Add { key_package_bytes: Vec<u8> },
    AddPending ,
    Remove { index: u32 },
    Update,
    RetrieveRatchetTree,
    ApplicationMsg { data: Vec<u8> },
    BroadcastKeyPackage,
}

pub fn parse_command(buffer: &[u8]) -> Result<Command, Error> {
    if buffer.is_empty() {
        return Err(Error::msg("Empty command. Nothing in received buffer."));
    }

    let op_code = buffer[0];
    let payload = &buffer[1..];

    match MlsOperation::try_from(op_code).map_err(|_| "Invalid opcode").unwrap() {
        MlsOperation::Add => Ok(Command::Add {
                        key_package_bytes: payload.to_vec(),
            }),
        MlsOperation::AddPending => Ok(Command::AddPending),
        MlsOperation::Remove => {
                if payload.len() < 4 {
                    return Err(Error::msg("Invalid Remove payload. Should be u32 (4 bytes long)"))
                }
                let index = u32::from_be_bytes(payload[..4].try_into().unwrap());
                Ok(Command::Remove { index })
            }
        MlsOperation::Update => Ok(Command::Update),
        MlsOperation::RetrieveRatchetTree => Ok(Command::RetrieveRatchetTree),
        MlsOperation::ApplicationMsg => Ok(Command::ApplicationMsg {
                data: payload.to_vec(),
            }),
        MlsOperation::BroadcastKeyPackage => Ok(Command::BroadcastKeyPackage),
        }
}

pub fn serialize_command(cmd: &Command) -> Vec<u8> {
    match cmd {
        Command::Add { key_package_bytes } => {
                        let mut buf = vec![MlsOperation::Add as u8];
                        buf.extend_from_slice(key_package_bytes);
                        buf
            }
        Command::Remove { index } => {
                let mut buf = vec![MlsOperation::Remove as u8];
                buf.extend(&index.to_be_bytes());
                buf
            }
        Command::RetrieveRatchetTree => vec![MlsOperation::RetrieveRatchetTree as u8],
        Command::Update => { vec![MlsOperation::Update as u8] },
        Command::AddPending => { vec![MlsOperation::AddPending as u8]},
        Command::ApplicationMsg { data } => {
                let mut buf = vec![MlsOperation::ApplicationMsg as u8];
                buf.extend_from_slice(data);
                buf
            }
        Command::BroadcastKeyPackage => vec![MlsOperation::BroadcastKeyPackage as u8],
    }
}

/*
How to:

*/


#[tokio::main]
async fn main() -> Result<()> {
    use tokio::{signal, io::{self, AsyncBufReadExt, BufReader}};
    use std::sync::Arc;

    env_logger::init();
    log::info!("MLS Control CLI started. Type commands or Ctrl-C to exit.");
    log::info!(
        "\nAvailable Commands:
      b            → Broadcast KeyPackage
      a            → Add Pending
      r            → Retrieve Ratchet Tree
      u            → Update
      rm <index>   → Remove member at index
      m <msg>      → Send application message
      + <file>     → Add KeyPackage from file
    
    Example: 12 b          (broadcast to {ip_prefix}.12:8000)
             4 rm 2        (remove member 2 from {ip_prefix}.4)
             9 m Hello     (send app msg to {ip_prefix}.9)
             7 + ./kp.bin  (add KeyPackage to {ip_prefix}.7)",
        ip_prefix = IP_PREFIX
    );
    

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    loop {
        select! {
            _ = signal::ctrl_c() => {
                log::info!("Shutdown requested. Exiting.");
                break;
            }

            line = lines.next_line() => {
                match line {
                    Ok(Some(input)) => {
                        if let Err(e) = handle_input(input.trim(), &socket).await {
                            log::error!("Failed to process command: {}", e);
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        log::error!("Error reading input: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_input(input: &str, socket: &UdpSocket) -> Result<()> {
    let mut parts = input.trim().split_whitespace();

    // Expect the first part to be the "x" in 10.10.0.x:8000
    let ip_suffix = parts.next().ok_or_else(|| Error::msg(format!("Missing node ID (x in {IP_PREFIX}.x)")))?;
    let ip: String = format!("{IP_PREFIX}.{ip_suffix}:8000");

    // Expect the next part to be the command letter
    let cmd = parts.next().ok_or_else(|| Error::msg("Missing command"))?;

    // Parse the rest of the command based on the letter
    let command = match cmd {
        "b" => Command::BroadcastKeyPackage,
        "a" => Command::AddPending,
        "r" => Command::RetrieveRatchetTree,
        "u" => Command::Update,
        "rm" => {
            let index = parts.next().ok_or_else(|| Error::msg("Missing index for remove"))?;
            let index = index.parse::<u32>()?;
            Command::Remove { index }
        }
        "m" => {
            let data = parts.collect::<Vec<_>>().join(" ");
            Command::ApplicationMsg { data: data.into_bytes() }
        }
        "+" => {
            let file_path = parts.next().ok_or_else(|| Error::msg("Missing file path for add"))?;
            let key_package_bytes = tokio::fs::read(file_path).await?;
            Command::Add { key_package_bytes }
        }
        _ => return Err(Error::msg("Unknown command")),
    };

    // Serialize and send the command
    let buf = serialize_command(&command);
    socket.send_to(&buf, &ip).await?;
    log::info!("✅ Sent command '{:?}' to {ip}", command);
    Ok(())
}

