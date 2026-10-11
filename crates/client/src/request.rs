//! What a client is asked: JSON objects tagged by `cmd`, and with the `clap` feature, a command line's subcommands.

use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes, into a group: a new one unless --group is given
    #[cfg_attr(feature = "clap", command(display_order = 10))]
    Invite {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        /// What a new group shares: a chat (messages in order), or a kind a plugin of this session supports, such as a doc (one text everyone edits at once)
        #[cfg_attr(feature = "clap", arg(long, default_value = "chat", conflicts_with = "group"))]
        #[serde(default = "chat")]
        kind: String,
        /// The new group's name
        #[cfg_attr(feature = "clap", arg(long, conflicts_with = "group"))]
        name: Option<String>,
        /// For the new group's kind: a doc's file, kept in step with the doc, and its first text if it exists [default: a new file in the session's state]
        #[cfg_attr(feature = "clap", arg(conflicts_with = "group"))]
        #[serde(default)]
        args: Vec<String>,
        /// The command's directory, which the arguments are relative to
        #[cfg_attr(feature = "clap", arg(skip))]
        #[serde(default)]
        cwd: String,
        /// Days members carry a new group's messages and files for one another
        #[cfg_attr(feature = "clap", arg(long, default_value_t = 7, conflicts_with = "group"))]
        #[serde(default = "carry")]
        carry: u32,
        /// The new group's membership service [default: listen's]
        #[cfg_attr(feature = "clap", arg(long, conflicts_with = "group"))]
        membership: Option<String>,
        /// Only the identity with this id, as `members` shows it, can redeem the link
        #[cfg_attr(feature = "clap", arg(long, value_name = "IDENTITY"))]
        to: Option<String>,
        /// Also show the link as a QR code, on stderr
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        qr: bool,
    },
    /// Join a group through an invite link
    #[cfg_attr(feature = "clap", command(display_order = 11))]
    Join {
        target: String,
        /// For the group's kind: a doc's new file to keep in step with it [default: a new file in the session's state]
        #[serde(default)]
        args: Vec<String>,
        #[cfg_attr(feature = "clap", arg(skip))]
        #[serde(default)]
        cwd: String,
    },
    /// List members of a group
    #[cfg_attr(feature = "clap", command(display_order = 14))]
    Members {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
    },
    /// List this session's groups
    #[cfg_attr(feature = "clap", command(display_order = 15))]
    Groups,
    /// Remove a member (by fingerprint or name) from a group
    #[cfg_attr(feature = "clap", command(display_order = 16))]
    Remove {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        member: String,
    },
    /// Leave a group; with --end, end it for everyone: remove the other members, and leave
    #[cfg_attr(feature = "clap", command(display_order = 17))]
    Leave {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        end: bool,
    },
    /// Name the group, for everyone in it
    #[cfg_attr(feature = "clap", command(display_order = 18))]
    Name {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        name: String,
    },
    /// The members online in each group, and what only this session holds
    #[cfg_attr(feature = "clap", command(display_order = 21))]
    Status,
    /// This device's identity: create one, invite another device to it, list its devices, take one off it, leave it, or rename this device
    #[cfg_attr(feature = "clap", command(display_order = 22))]
    Identity {
        #[cfg_attr(feature = "clap", command(subcommand))]
        op: IdentityOp,
    },
    /// A certificate of a session of this device, with MLS key `key`, by the device's key on its identity: for the device.
    #[cfg_attr(feature = "clap", command(skip))]
    Certify { key: Bytes },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(rename_all = "snake_case")]
pub enum IdentityOp {
    /// Start an identity with this device as its first device; a device is on one identity at a time
    Create {
        name: String,
        /// The membership service that keeps its public log [default: listen's]
        #[cfg_attr(feature = "clap", arg(long))]
        membership: Option<String>,
    },
    /// Make a device link, valid for 10 minutes, for another device (a machine or a browser) to join this identity
    Invite {
        /// Also show the link as a QR code, on stderr
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        qr: bool,
    },
    /// This device's identity, and its devices
    List,
    /// Take another device, by key or name, off the identity, whose public log then lists the others
    Remove { device: String },
    /// Take this device off its identity: its sessions leave the groups they are in as it first; the identity ends if this is its only device
    Leave,
    /// Rename this device, as its identity's devices and members of its sessions' groups see it
    Rename { name: String },
}

fn chat() -> String {
    lmk_proto::group::CHAT.into()
}

fn carry() -> u32 {
    7
}

impl Request {
    /// Whether only the device's node answers it.
    pub fn for_device(&self) -> bool {
        match self {
            // A session leaves its own groups first.
            Request::Identity { op: IdentityOp::Leave } => false,
            Request::Identity { .. } | Request::Certify { .. } => true,
            Request::Join { target, .. } => lmk_proto::links::Invite::parse(target.trim()).is_ok_and(|invite| invite.device),
            _ => false,
        }
    }
}
