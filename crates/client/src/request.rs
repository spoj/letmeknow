//! What a client is asked: JSON objects tagged by `cmd`, and with the `clap` feature, a command line's subcommands.

use lmk_node::identity::Add;
use lmk_proto::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes, into a chat: a new one unless --group is given
    #[cfg_attr(feature = "clap", command(display_order = 10))]
    Invite {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        /// The new chat's name
        #[cfg_attr(feature = "clap", arg(long, conflicts_with = "group"))]
        name: Option<String>,
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
    Join { target: String },
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
    /// Add a session of one of your devices to the group, within a week: a running session by its handle, or a device by
    /// its name or key, with the session it runs, or else the one that next runs there
    #[cfg_attr(feature = "clap", command(display_order = 19))]
    Add {
        /// A session's handle, or a device, as `identity list` shows them
        target: String,
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
    },
    /// This device's identity: create one, invite another device to it, list its devices, take one off it, leave it, or rename this device
    #[cfg_attr(feature = "clap", command(display_order = 22))]
    Identity {
        #[cfg_attr(feature = "clap", command(subcommand))]
        op: IdentityOp,
    },
    /// Device-signed claims for this actual session key, named from committed private identity state, not caller labels.
    #[cfg_attr(feature = "clap", command(skip))]
    Certify { key: Bytes },
    /// `add`'s invite, which the device's node hands to the device it names, in the identity group.
    #[cfg_attr(feature = "clap", command(skip))]
    Deliver { add: Add },
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
    /// Make a device link, valid for 10 minutes, for another device to join this identity
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
    /// Rename private identity claims, or with --device this device; offline sessions refresh their leaves after resume
    Rename {
        name: String,
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        device: bool,
    },
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
            Request::Identity { .. } | Request::Certify { .. } | Request::Deliver { .. } => true,
            Request::Join { target, .. } => lmk_proto::links::Invite::parse(target.trim()).is_ok_and(|invite| invite.device),
            _ => false,
        }
    }
}
