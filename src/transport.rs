use std::io::{Read, Write};

use crate::types::{AMessage, APacket};
use anyhow::{Ok, Result};

pub struct ATransport<S> {
    stream: S,
}

impl<S: Read + Write> ATransport<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn stream(self) -> S {
        self.stream
    }

    pub fn read_apacket(&mut self) -> Result<APacket> {
        let mut buf = [0; 24];
        self.stream.read_exact(&mut buf)?;
        let msg = AMessage::from(&buf)?;
        let length = msg.data_length as usize;
        let mut payload = vec![0; length];
        self.stream.read_exact(&mut payload)?;
        Ok(APacket { msg, payload })
    }

    pub fn send_apacket(&mut self, mut packet: APacket) -> Result<usize> {
        packet.msg.magic = packet.msg.command ^ 0xffffffff;
        let mut bytes = vec![];
        bytes.append(&mut packet.msg.bytes()?);
        bytes.append(&mut packet.payload.clone());
        Ok(self.stream.write(&bytes)?)
    }
}
