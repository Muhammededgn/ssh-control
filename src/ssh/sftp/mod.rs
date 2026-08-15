pub mod client;
pub mod wire;

pub use client::{FileHandle, RemoteEntry, SftpClient};
pub use wire::FileKind;

use russh::client as russh_client;
use russh::{Channel, ChannelMsg};

use super::client::Handler;
use crate::error::{AppError, Result};

/// The only russh-aware part of the SFTP stack: opens a channel, starts the
/// subsystem, and hands the resulting byte stream to `SftpClient`.
///
/// Two details here are load-bearing.
///
/// `request_subsystem` does **not** await the server's answer — it only sets
/// the want-reply bit, and the `Success`/`Failure` arrives later as a
/// `ChannelMsg`. And `into_stream()` reads through a receiver that silently
/// discards every message that is not data, so a `Failure` left unread simply
/// disappears. A server without an sftp subsystem would then look like an
/// unexplained EOF half way through the handshake, which is why the reply is
/// consumed here, before the channel becomes a stream.
pub async fn open_session(
    handle: &mut russh_client::Handle<Handler>,
) -> Result<SftpClient<russh::ChannelStream<russh_client::Msg>>> {
    let mut channel: Channel<russh_client::Msg> = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => {
                return Err(AppError::Sftp("the server refused to start its sftp subsystem".into()));
            }
            // Anything else before the reply is not ours to interpret; only a
            // closed channel is fatal.
            Some(_) => continue,
            None => return Err(AppError::Sftp("the channel closed before the sftp subsystem started".into())),
        }
    }

    SftpClient::init(channel.into_stream()).await
}
