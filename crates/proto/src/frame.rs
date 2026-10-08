use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame a reader takes.
pub const MAX_FRAME: u32 = 16 << 20;

/// The first frame on every stream: which exchange it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
    pub stream: Stream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Membership,
    Peer,
    Invite,
}

pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("our frames serialize");
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

pub async fn write<T: Serialize, W: AsyncWrite + Unpin>(w: &mut W, value: &T) -> Result<()> {
    w.write_all(&encode(value)).await?;
    Ok(())
}

pub async fn read<T: DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> Result<T> {
    let len = r.read_u32().await?;
    ensure!(len <= MAX_FRAME, "a frame of {len} bytes exceeds {MAX_FRAME}");
    let mut body = vec![0; len as usize];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let mut buf = Vec::new();
        write(&mut buf, &Open { stream: Stream::Peer }).await.unwrap();
        assert_eq!(&buf[4..], br#"{"stream":"peer"}"#);
        let open: Open = read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(open.stream, Stream::Peer);
    }
}
