use std::{collections::HashMap, io::Cursor, net::SocketAddr, sync::Arc};

use anyhow::Context as _;
use byteorder::{LE, ReadBytesExt};
use steam_types::{
    CMsgMulti, CMsgProtoBufHeader, EMsg,
    prost::{Message as _, bytes::Buf},
};
use tokio::{
    io::{BufReader, BufWriter},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{Mutex, RwLock, mpsc, oneshot},
    task::JoinHandle,
};

use crate::{JobId, SessionId, SteamId, crypto};

pub mod tcp;

type SharedKey = Arc<RwLock<Option<Vec<u8>>>>;

#[derive(Debug, Clone)]
pub enum Header {
    EMsg {
        target_job: JobId,
        source_job: JobId,
        steam_and_session: Option<(SteamId, SessionId)>,
    },
    Proto(Box<CMsgProtoBufHeader>),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub emsg: EMsg,
    pub header: Header,
    pub body: Vec<u8>,
}

impl Message {
    pub fn job_target(&self) -> Option<JobId> {
        match &self.header {
            Header::EMsg { target_job, .. } => Some(*target_job),
            Header::Proto(cmsg_proto_buf_header) => cmsg_proto_buf_header.jobid_target,
        }
    }
}

pub struct Transport {
    read_job: JoinHandle<()>,
    write_job: JoinHandle<()>,

    writer_tx: mpsc::Sender<Message>,

    session_key: SharedKey,
}

impl Transport {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<(Self, mpsc::Receiver<Message>)> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        let (read, write) = socket.connect(addr).await?.into_split();

        let read = BufReader::new(read);
        let write = BufWriter::new(write);

        let session_key = Arc::new(RwLock::new(None));

        let (reader_tx, reader_rx) = mpsc::channel(1024);
        let (writer_tx, writer_rx) = mpsc::channel(1024);

        Ok((
            Self {
                read_job: Reader {
                    read,
                    session_key: session_key.clone(),
                    tx: reader_tx,
                }
                .spawn(),
                write_job: Writer {
                    write,
                    session_key: session_key.clone(),
                    rx: writer_rx,
                }
                .spawn(),
                writer_tx,

                session_key,
            },
            reader_rx,
        ))
    }

    pub async fn set_key(&self, key: impl Into<Vec<u8>>) {
        self.session_key.write().await.replace(key.into());
    }

    pub async fn send(&self, message: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.writer_tx.send(message).await
    }
}

trait Service: Sized + Send
where
    Self: 'static,
{
    fn service(self) -> impl std::future::Future<Output = anyhow::Result<()>> + std::marker::Send;
    fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.service().await {
                println!("reader service closed - {e:?}");
            }
        })
    }
}

const MAGIC: &[u8] = b"VT01";
const PROTO_MASK: u32 = 0x80000000;

struct Writer {
    write: BufWriter<OwnedWriteHalf>,
    session_key: SharedKey,
    rx: mpsc::Receiver<Message>,
}
impl Service for Writer {
    async fn service(mut self) -> anyhow::Result<()> {
        while let Some(msg) = self.rx.recv().await {
            self.send(msg).await?;
        }
        Ok(())
    }
}

impl Writer {
    pub async fn send(&mut self, mut message: Message) -> anyhow::Result<()> {
        use byteorder::WriteBytesExt as _;
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
    pub async fn send_raw(&mut self, bytes: impl AsRef<[u8]>) -> anyhow::Result<()> {
        let bytes = bytes.as_ref();
        use tokio::io::AsyncWriteExt as _;
        match self.session_key.read().await.as_ref() {
            Some(key) => {
                let bytes = crypto::symmetric_encrypt_with_hmac_iv(bytes, key);

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
}

struct Reader {
    read: BufReader<OwnedReadHalf>,
    session_key: SharedKey,
    tx: mpsc::Sender<Message>,
}

impl Service for Reader {
    async fn service(mut self) -> anyhow::Result<()> {
        use tokio::io::AsyncReadExt;
        loop {
            let msg_len =
                usize::try_from(self.read.read_u32_le().await.context("reading msg len")?).unwrap();
            let mut magic = [0_u8; 4];
            self.read.read_exact(&mut magic).await?;
            if magic != MAGIC {
                println!("{magic:x?}");
                anyhow::bail!("Connection out of sync");
            }

            println!("[reader] got msg of len {msg_len}");
            let mut msg = vec![0; msg_len];
            self.read.read_exact(&mut msg).await?;

            if let Some(key) = self.session_key.read().await.as_ref() {
                // println!("[reader] decrypting...");
                msg = crypto::symmetric_decrypt(&msg, key, true)?;
            }

            let mut msg = Cursor::new(msg);
            let raw_emsg = ReadBytesExt::read_u32::<LE>(&mut msg)?;

            let emsg = EMsg::try_from((raw_emsg & !PROTO_MASK) as i32)?;
            let is_protobuf = (raw_emsg & PROTO_MASK) != 0;

            let header = if is_protobuf {
                let len = ReadBytesExt::read_u32::<LE>(&mut msg)?;
                let proto =
                    CMsgProtoBufHeader::decode(Buf::take(&mut msg, len.try_into().unwrap()))?;
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
            let message = Message {
                emsg,
                header,
                body: msg.into_inner().drain(pos..).collect(),
            };

            if message.emsg == EMsg::KEMsgMulti {
                let mut body = CMsgMulti::decode(Cursor::new(message.body))?;
                let Some(mut payload) = body.message_body else {
                    println!("multi with no message body?");
                    return Ok(());
                };
                if let Some(size_unzipped) = body.size_unzipped {
                    use std::io::Read as _;
                    let mut final_payload = Vec::with_capacity(size_unzipped.try_into().unwrap());
                    let mut reader = flate2::read::GzDecoder::new(Cursor::new(&payload));
                    reader.read_to_end(&mut final_payload)?;
                    std::mem::swap(&mut payload, &mut final_payload);
                }
                println!("multi!!");
                return Ok(());
            }
            // println!("[reader] forwarding...");
            self.tx.send(message).await?;
        }
    }
}
