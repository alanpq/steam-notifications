use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64},
    },
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
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    crypto::SessionKey,
    transport::{Header, Message},
};

pub mod crypto;
pub mod transport;

struct Client {
    conn: transport::Transport,
    msg_handle: JoinHandle<()>,
    msg_rx: mpsc::Receiver<Message>,
    job_counter: AtomicU64,
    callbacks: CallbackMap,
}

type CallbackMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Message>>>>;
impl Client {
    pub fn new(connection: transport::Transport, mut message_rx: mpsc::Receiver<Message>) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let callbacks = CallbackMap::default();
        Self {
            conn: connection,
            callbacks: callbacks.clone(),
            msg_rx: rx,
            msg_handle: tokio::spawn(async move {
                while let Some(msg) = message_rx.recv().await {
                    if let Some(job_target) = msg.job_target()
                        && let Some(callback) = callbacks.lock().await.remove(&job_target)
                    {
                        let _ = callback.send(msg);
                    } else {
                        let _ = tx.send(msg).await;
                    }
                }
            }),
            job_counter: Default::default(),
        }
    }

    pub async fn read(&mut self) -> Option<Message> {
        self.msg_rx.recv().await
    }

    pub async fn call<M: Method>(&self, method: M) -> anyhow::Result<Message> {
        let job_id = self
            .job_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let header = Header::Proto(
            CMsgProtoBufHeader {
                target_job_name: Some(M::TARGET_JOB_NAME.to_string()),
                jobid_source: Some(job_id),
                realm: Some(1),
                ..Default::default()
            }
            .into(),
        );

        let (tx, rx) = oneshot::channel();
        self.callbacks.lock().await.insert(job_id, tx);

        self.conn
            .send(Message {
                emsg: EMsg::KEMsgServiceMethodCallFromClientNonAuthed,
                header,
                body: method.encode_to_vec(),
            })
            .await?;

        Ok(rx.await?)
    }
}

trait Method: steam_types::prost::Message {
    const TARGET_JOB_NAME: &'static str;
}

impl Method for CAuthenticationGetPasswordRsaPublicKeyRequest {
    const TARGET_JOB_NAME: &'static str = "Authentication.GetPasswordRSAPublicKey#1";
}

const MAGIC: &[u8] = b"VT01";
const PROTO_MASK: u32 = 0x80000000;

const JOBID_NONE: JobId = 18446744073709551615;

type JobId = u64;
type SteamId = u64;
type SessionId = u32;

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

async fn encrypt_password(client: &mut Client, account_name: String) -> anyhow::Result<()> {
    println!("sending encrypt password req for {account_name:?}");
    let key = client
        .call(CAuthenticationGetPasswordRsaPublicKeyRequest {
            account_name: Some(account_name),
        })
        .await?;

    println!("{key:?}");

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
    let (conn, msg_rx) = transport::Transport::connect(addr).await.unwrap();
    let mut client = Client::new(conn, msg_rx);
    println!("connected to CM.");

    // let hello = steam_types::CMsgClientHello {
    //     protocol_version: Some(PROTOCOL_VERSION),
    // };
    //
    // conn.send_proto(hello).await.unwrap();

    let account_name = std::env::var("STEAM_ACCOUNT_NAME").unwrap();
    let account_password = std::env::var("STEAM_ACCOUNT_PASSWORD").unwrap();

    let mut tmp_session_key = None;

    println!("reading next m");
    while let Some(msg) = client.read().await {
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

                    client
                        .conn
                        .send(Message {
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

                    client
                        .conn
                        .set_key(
                            tmp_session_key
                                .take()
                                .expect("session key request must have been made")
                                .plain,
                        )
                        .await;

                    println!("encryption success, logging on...");

                    client
                        .conn
                        .send(Message {
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
                    encrypt_password(&mut client, account_name.clone()).await?;

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
    Ok(())
}
