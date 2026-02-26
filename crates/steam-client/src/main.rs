use std::{
    io::{Cursor, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    time::Instant,
};

use anyhow::Context as _;
use byteorder::{LE, ReadBytesExt, WriteBytesExt as _};
use itertools::Itertools;
use reqwest::Url;
use serde::Serialize;
use steam_types::{
    CAuthenticationBeginAuthSessionViaCredentialsRequest, CAuthenticationDeviceDetails,
    CAuthenticationGetPasswordRsaPublicKeyRequest, CMsgClientHello, CMsgProtoBufHeader,
    EAuthTokenPlatformType, EMsg, ESessionPersistence,
    prost::{Message as _, bytes::Buf},
};
use tokio::{
    io::{BufReader, BufWriter},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::crypto::SessionKey;

pub mod crypto;

struct Client {}

struct TCPConnection {
    read: BufReader<OwnedReadHalf>,
    write: BufWriter<OwnedWriteHalf>,
    session_key: Option<SessionKey>,
}

const MAGIC: &[u8] = b"VT01";
const PROTO_MASK: u32 = 0x80000000;

const JOBID_NONE: JobId = 18446744073709551615;

type JobId = u64;
type SteamId = u64;
type SessionId = u32;

#[derive(Debug)]
enum Header {
    EMsg {
        target_job: JobId,
        source_job: JobId,
        steam_and_session: Option<(SteamId, SessionId)>,
    },
    Proto(Box<CMsgProtoBufHeader>),
}

#[derive(Debug)]
struct Message {
    emsg: EMsg,
    header: Header,
    body: Vec<u8>,
}

impl TCPConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        let (read, write) = socket.connect(addr).await?.into_split();

        let read = BufReader::new(read);
        let write = BufWriter::new(write);

        Ok(Self {
            read,
            write,
            session_key: None,
        })
    }

    pub async fn send_proto(
        &mut self,
        message: impl steam_types::prost::Message,
    ) -> anyhow::Result<()> {
        let len = message.encoded_len();
        let mut buf = Vec::with_capacity(4 + 4 + len);
        buf.write_u32::<LE>(len as _)?;
        buf.write_all(MAGIC)?;
        message.encode(&mut buf)?;

        let mut buf = Cursor::new(buf);
        {
            use tokio::io::AsyncWriteExt as _;
            self.write.write_all_buf(&mut buf).await?;
            self.write.flush().await?;
        }
        Ok(())
    }

    pub async fn send_raw(&mut self, bytes: impl AsRef<[u8]>) -> anyhow::Result<()> {
        let bytes = bytes.as_ref();
        use tokio::io::AsyncWriteExt as _;
        match self.session_key.as_ref() {
            Some(key) => {
                let bytes = crypto::symmetric_encrypt_with_hmac_iv(bytes, &key.plain);

                self.write
                    .write_u32_le(bytes.len().try_into().unwrap())
                    .await?;
                self.write.write_all_buf(&mut Cursor::new(MAGIC)).await?;
                self.write.write_all_buf(&mut Cursor::new(bytes)).await?;
            }
            None => {
                self.write
                    .write_u32_le(bytes.len().try_into().unwrap())
                    .await?;
                self.write.write_all_buf(&mut Cursor::new(MAGIC)).await?;
                self.write.write_all_buf(&mut Cursor::new(bytes)).await?;
            }
        }
        self.write.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, mut message: Message) -> anyhow::Result<()> {
        println!("-> \x1b[34m{:?}\x1b[0m: {:?}", message.emsg, message.header);
        match message.header {
            Header::EMsg {
                target_job,
                source_job,
                steam_and_session,
            } => {
                let mut buf = if message.emsg == EMsg::KEMsgChannelEncryptResponse {
                    let mut buf = Vec::with_capacity(4 + 8 + 8);
                    buf.write_u32::<LE>(i32::from(message.emsg) as u32)?;
                    buf.write_u64::<LE>(target_job)?;
                    buf.write_u64::<LE>(source_job)?;
                    buf
                } else {
                    let mut buf = Vec::with_capacity(4 + 1 + 2 + 8 + 8 + 1 + 8 + 4);
                    buf.write_u32::<LE>(i32::from(message.emsg) as u32)?;
                    buf.write_u8(36)?;
                    buf.write_u16::<LE>(2)?;
                    buf.write_u64::<LE>(target_job)?;
                    buf.write_u64::<LE>(source_job)?;
                    buf.write_u8(239)?;
                    let (steam_id, session_id) = steam_and_session.unwrap_or_default();
                    buf.write_u64::<LE>(steam_id)?;
                    buf.write_u32::<LE>(session_id)?;
                    buf
                };
                buf.append(&mut message.body);
                self.send_raw(&buf).await?;
            }
            Header::Proto(proto) => {
                let mut header = proto.encode_to_vec();
                let mut buf = Vec::with_capacity(4 + 4 + header.len() + message.body.len());
                buf.write_u32::<LE>(i32::from(message.emsg) as u32 | PROTO_MASK)?;
                buf.write_u32::<LE>(header.len().try_into().unwrap())?;
                buf.append(&mut header);
                buf.append(&mut message.body);
                self.send_raw(&buf).await?;
            }
        }

        Ok(())
    }

    pub async fn read_message(&mut self) -> anyhow::Result<Message> {
        use tokio::io::AsyncReadExt;
        let msg_len =
            usize::try_from(self.read.read_u32_le().await.context("reading msg len")?).unwrap();
        let mut magic = [0_u8; 4];
        self.read.read_exact(&mut magic).await?;
        if magic != MAGIC {
            println!("{magic:x?}");
            anyhow::bail!("Connection out of sync");
        }

        println!("got msg of len {msg_len}");
        let mut msg = vec![0; msg_len];
        self.read.read_exact(&mut msg).await?;

        if let Some(key) = self.session_key.as_ref() {
            msg = crypto::symmetric_decrypt(&msg, &key.plain, true)?;
        }

        let mut msg = Cursor::new(msg);
        let raw_emsg = ReadBytesExt::read_u32::<LE>(&mut msg)?;

        let emsg = EMsg::try_from((raw_emsg & !PROTO_MASK) as i32)?;
        let is_protobuf = (raw_emsg & PROTO_MASK) != 0;

        let header = if is_protobuf {
            let len = ReadBytesExt::read_u32::<LE>(&mut msg)?;
            let proto = CMsgProtoBufHeader::decode(Buf::take(&mut msg, len.try_into().unwrap()))?;
            Header::Proto(proto.into())
        } else {
            match emsg {
                EMsg::KEMsgChannelEncryptRequest | EMsg::KEMsgChannelEncryptResult => {
                    Header::EMsg {
                        target_job: ReadBytesExt::read_u64::<LE>(&mut msg)?,
                        source_job: ReadBytesExt::read_u64::<LE>(&mut msg)?,
                        steam_and_session: None,
                    }
                }
                _ => {
                    let _header_size = ReadBytesExt::read_u8(&mut msg)?; // always 36
                    let _header_version = ReadBytesExt::read_u16::<LE>(&mut msg)?; // always 2

                    let target_job = ReadBytesExt::read_u64::<LE>(&mut msg)?;
                    let source_job = ReadBytesExt::read_u64::<LE>(&mut msg)?;

                    let _canary = ReadBytesExt::read_u8(&mut msg)?; // always 239
                    Header::EMsg {
                        target_job,
                        source_job,
                        steam_and_session: Some((
                            ReadBytesExt::read_u64::<LE>(&mut msg)?,
                            ReadBytesExt::read_u32::<LE>(&mut msg)?,
                        )),
                    }
                }
            }
        };

        let pos = usize::try_from(msg.position()).unwrap();
        Ok(Message {
            emsg,
            header,
            body: msg.into_inner().drain(pos..).collect(),
        })

        // EMsg::decode();
        // steam_types::prost::Message::dec

        // Ok(msg)
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
#[derive(Serialize)]
struct GetPasswordRSAPublicKey {
    format: String,
    account_name: String,
}

async fn encrypt_password(conn: &mut TCPConnection, account_name: String) -> anyhow::Result<()> {
    // let body = serde_qs::to_string(&GetPasswordRSAPublicKey {
    //     format: "vdf".into(),
    //     account_name,
    // })?;
    // let rsa_info = reqwest::get(
    //     format!("https://{API_HOSTNAME}/Authentication/GetPasswordRSAPublicKey/v1?{body}")
    //         .parse::<Url>()
    //         .unwrap(),
    // )
    // .await?
    // .error_for_status()?;
    // let rsa_info = rsa_info.text().await?;
    // let rsa_info = steam_vdf_parser::parse_text(rsa_info.trim())?;
    // dbg!(&rsa_info);

    println!("sending encrypt password req for {account_name:?}");
    conn.send(Message {
        emsg: EMsg::KEMsgServiceMethodCallFromClientNonAuthed,
        header: Header::Proto(
            CMsgProtoBufHeader {
                target_job_name: Some("Authentication.GetPasswordRSAPublicKey#1".into()),
                jobid_source: Some(1234),
                jobid_target: Some(JOBID_NONE),
                client_sessionid: Some(0),
                steamid: Some(0),
                realm: Some(1),
                ..Default::default()
            }
            .into(),
        ),
        body: CAuthenticationGetPasswordRsaPublicKeyRequest {
            account_name: Some(account_name),
        }
        .encode_to_vec(),
    })
    .await?;
    tokio::io::AsyncWriteExt::flush(&mut conn.write).await?;
    println!("reading msg");
    let msg = conn.read_message().await?;
    dbg!(&msg);

    //
    // let rsa_key = rsa::RsaPublicKey::new(rsa_info.get_str(path), e)
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let body = serde_qs::to_string(&GetCMListForConnectRequest {
        format: "vdf".into(),
        cellid: "0".into(),
    })?;
    let server_list = reqwest::get(
        format!("https://{API_HOSTNAME}/ISteamDirectory/GetCMListForConnect/v1?{body}")
            .parse::<Url>()
            .unwrap(),
    )
    .await?
    .error_for_status()?;

    let server_list = server_list.text().await?;
    // println!("{server_list}");

    let server_list = steam_vdf_parser::parse_text(server_list.trim())?;
    // println!("{server_list:?}");

    let server_list = server_list.get("serverlist").unwrap().as_obj().unwrap();
    let server = server_list
        .values()
        .filter(|s| {
            s.get_str(&["realm"]) == Some("steamglobal")
                && s.get_str(&["type"])
                    .is_some_and(|typ| ["netfilter"].contains(&typ)) // normally also includes "websockets"
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
    println!("{server:#?}");

    let addr = server
        .get_str(&["endpoint"])
        .unwrap()
        .to_socket_addrs()?
        .next()
        .unwrap();
    println!("addr: {addr:?}");
    let mut conn = TCPConnection::connect(addr).await.unwrap();
    println!("connected to CM.");

    // let hello = steam_types::CMsgClientHello {
    //     protocol_version: Some(PROTOCOL_VERSION),
    // };
    //
    // conn.send_proto(hello).await.unwrap();

    let account_name = std::env::var("STEAM_ACCOUNT_NAME").unwrap();
    let account_password = std::env::var("STEAM_ACCOUNT_PASSWORD").unwrap();

    let mut tmp_session_key = None;

    loop {
        let msg = conn.read_message().await?;
        match msg.header {
            Header::Proto(proto) => {
                println!("<- proto: {proto:x?}");
            }
            header @ Header::EMsg {
                target_job,
                source_job,
                steam_and_session,
            } => match msg.emsg {
                EMsg::KEMsgChannelEncryptRequest => {
                    println!("{:x?}", msg.body);
                    let mut body = Cursor::new(msg.body);

                    let protocol = body.read_u32::<LE>()?;
                    let universe = body.read_u32::<LE>()?;

                    let mut nonce = [0; 16];
                    body.read_exact(&mut nonce)?;

                    println!(
                        "Channel encrypt request: protocol {protocol}, universe {universe}, nonce: {nonce:x?}, {} remaining bytes",
                        body.remaining()
                    );

                    let session_key = crypto::generate_session_key(Some(&nonce))?;
                    let key_crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
                        .checksum(&session_key.encrypted);

                    let mut enc_resp: Vec<u8> =
                        Vec::with_capacity(4 + 4 + session_key.encrypted.len() + 4 + 4);
                    enc_resp.write_u32::<LE>(protocol)?;
                    enc_resp.write_u32::<LE>(session_key.encrypted.len().try_into().unwrap())?;
                    enc_resp.write_all(&session_key.encrypted)?;
                    enc_resp.write_u32::<LE>(key_crc)?;
                    enc_resp.write_u32::<LE>(0)?;

                    tmp_session_key.replace(session_key);

                    conn.send(Message {
                        emsg: EMsg::KEMsgChannelEncryptResponse,
                        header: Header::EMsg {
                            target_job: JOBID_NONE,
                            source_job: JOBID_NONE,
                            steam_and_session: Some((76561198312268312, 0)),
                        },
                        body: enc_resp,
                    })
                    .await?;
                }
                EMsg::KEMsgChannelEncryptResult => {
                    let mut body = Cursor::new(msg.body);
                    let eresult = body.read_u32::<LE>()?;
                    if eresult != 1 {
                        // TODO: EResult definition
                        anyhow::bail!("encryption failed - {eresult}");
                    }

                    conn.session_key.replace(
                        tmp_session_key
                            .take()
                            .expect("session key request must have been made"),
                    );

                    println!("encryption success, logging on...");

                    conn.send(Message {
                        emsg: EMsg::KEMsgClientHello,
                        header: Header::Proto(
                            CMsgProtoBufHeader {
                                jobid_source: Some(JOBID_NONE),
                                jobid_target: Some(JOBID_NONE),
                                client_sessionid: Some(0),
                                steamid: Some(0),
                                ..Default::default()
                            }
                            .into(),
                        ),
                        body: CMsgClientHello {
                            protocol_version: Some(PROTOCOL_VERSION),
                        }
                        .encode_to_vec(),
                    })
                    .await?;
                    encrypt_password(&mut conn, account_name.clone()).await?;

                    // let now = Instant::now();
                    //
                    // let data = CAuthenticationBeginAuthSessionViaCredentialsRequest {
                    //     device_friendly_name: Some("TESAT CLIENT".into()),
                    //     account_name: Some(account_name),
                    //     encrypted_password: todo!(),
                    //     encryption_timestamp: todo!(),
                    //     remember_login: todo!(),
                    //     platform_type: Some(
                    //         EAuthTokenPlatformType::KEAuthTokenPlatformTypeSteamClient.into(),
                    //     ),
                    //     persistence: Some(
                    //         ESessionPersistence::KESessionPersistencePersistent.into(),
                    //     ),
                    //     website_id: Some("Unknown".into()),
                    //     device_details: Some(CAuthenticationDeviceDetails {
                    //         device_friendly_name: Some("TESAT CLIENT".into()),
                    //         platform_type: Some(
                    //             EAuthTokenPlatformType::KEAuthTokenPlatformTypeSteamClient.into(),
                    //         ),
                    //         os_type: Some(20), // win 11 TODO: EOSType definition
                    //         gaming_device_type: Some(1), // EGamingDeviceType full def is unknown,
                    //         // 1 seems to be desktop PC
                    //         client_count: None,
                    //         machine_id: todo!(),
                    //         app_type: todo!(),
                    //     }),
                    //     guard_data: todo!(),
                    //     language: todo!(),
                    //     qos_level: todo!(),
                    // };
                }
                _ => {
                    println!("<- emsg: {:?} -> {header:x?}", msg.emsg);
                }
            },
        }
    }
}
