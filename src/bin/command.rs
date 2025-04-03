use anyhow::{Error, Ok, Result};
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Sending command to {}", cli.ip);
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let command = match &cli.command {
        MlsCliCommand::Add { file } => {
            let key_package_bytes = tokio::fs::read(file).await?;
            Command::Add { key_package_bytes }
        }
        MlsCliCommand::Remove { index } => Command::Remove { index: *index },
        MlsCliCommand::Update => Command::Update,
        MlsCliCommand::RetrieveRatchetTree => Command::RetrieveRatchetTree,
        MlsCliCommand::AddPending => Command::AddPending,
        MlsCliCommand::ApplicationMsg { data } => {
            Command::ApplicationMsg { data: data.clone().into_bytes() }
        }
        MlsCliCommand::BroadcastKeyPackage => Command::BroadcastKeyPackage,
    };

    let bytes = serialize_command(&command);
    socket.send_to(&bytes, &cli.ip).await?;
    log::info!("Command sent!");

    Ok(())
}



