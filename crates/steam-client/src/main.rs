use std::{
    io::{Cursor, Write},
    net::SocketAddr,
};

use byteorder::{LE, WriteBytesExt as _};
use itertools::Itertools;
use reqwest::Url;
use serde::Serialize;
use steam_types::EMsg;
use tokio::io::AsyncReadExt;

struct Client {}

struct TCPConnection {
    stream: tokio::net::TcpStream,
}

const MAGIC: &[u8] = b"VT01";

impl TCPConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        let stream = socket.connect(addr).await?;

        Ok(Self { stream })
    }

    pub async fn send(&mut self, message: impl steam_types::prost::Message) -> anyhow::Result<()> {
        let len = message.encoded_len();
        let mut buf = Vec::with_capacity(4 + 4 + len);
        buf.write_u32::<LE>(len as _)?;
        buf.write_all(MAGIC)?;
        message.encode(&mut buf)?;

        let mut buf = Cursor::new(buf);
        tokio::io::AsyncWriteExt::write_all_buf(&mut self.stream, &mut buf).await?;
        Ok(())
    }

    pub async fn read_message(&mut self) -> anyhow::Result<Vec<u8>> {
        let msg_len = self.stream.read_u32_le().await? as usize;
        let mut magic = [0_u8; 4];
        self.stream.read_exact(&mut magic).await?;
        if magic != MAGIC {
            anyhow::bail!("Connection out of sync");
        }

        let mut msg = vec![0; msg_len];
        self.stream.read_exact(&mut msg).await?;

        EMsg::decode();
        // steam_types::prost::Message::dec

        Ok(msg)
    }
}

const PROTOCOL_VERSION: u32 = 65580;

const API_HOSTNAME: &str = "api.steampowered.com";
const USER_AGENT: &str = "Valve/Steam HTTP Client 1.0";

#[derive(Serialize)]
struct GetCMListForConnectRequest {
    format: String,
    cellid: String,
}

#[tokio::main]
async fn main() {
    let body = serde_qs::to_string(&GetCMListForConnectRequest {
        format: "vdf".into(),
        cellid: "0".into(),
    })
    .unwrap();
    let server_list = reqwest::get(
        format!("https://{API_HOSTNAME}/ISteamDirectory/GetCMListForConnect/v1?{body}")
            .parse::<Url>()
            .unwrap(),
    )
    .await
    .unwrap()
    .error_for_status()
    .unwrap();

    let server_list = server_list.text().await.unwrap();
    println!("{server_list}");

    let server_list = steam_vdf_parser::parse_text(server_list.trim()).unwrap();
    println!("{server_list:?}");

    let server_list = server_list.get("serverlist").unwrap().as_obj().unwrap();
    let server = server_list
        .values()
        .filter(|s| {
            s.get_str(&["realm"]) == Some("steamglobal")
                && s.get_str(&["type"])
                    .is_some_and(|typ| ["netfilter"].contains(&typ)) // normally also includes "netfilter"
            // && s.get_str(&["endpoint"]).is_some_and(|e| e.ends_with(":443"))
        })
        .sorted_by_cached_key(|s| {
            s.get_str(&["wtd_load"])
                .and_then(|load| load.parse::<f32>().ok())
                .map(|n| n as u32)
                .unwrap_or(u32::MAX)
        })
        .next()
        .unwrap();
    println!("{server:#?}",);

    let mut conn = TCPConnection::connect(server.get_str(&["endpoint"]).unwrap().parse().unwrap())
        .await
        .unwrap();

    let hello = steam_types::CMsgClientHello {
        protocol_version: Some(PROTOCOL_VERSION),
    };

    conn.send(hello).await.unwrap();

    let msg = conn.read_message().await.unwrap();
    println!("{msg:x?}");

    // steam_types::prost::Message
}
