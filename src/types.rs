use anyhow::{Ok, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::adb::*;

#[derive(Debug)]
pub struct AMessage {
    pub command: u32,     /* command identifier constant      */
    pub arg0: u32,        /* first argument                   */
    pub arg1: u32,        /* second argument                  */
    pub data_length: u32, /* length of payload (0 is allowed) */
    pub data_check: u32,  /* checksum of data payload         */
    pub magic: u32,       /* command ^ 0xffffffff             */
}

impl AMessage {
    fn new(command: u32) -> Self {
        AMessage {
            command,
            arg0: 0,
            arg1: 0,
            data_length: 0,
            data_check: 0,
            magic: 0,
        }
    }

    pub fn from(mut v: &[u8]) -> Result<Self> {
        let command = v.read_u32::<LittleEndian>()?;
        let arg0 = v.read_u32::<LittleEndian>()?;
        let arg1 = v.read_u32::<LittleEndian>()?;
        let data_length = v.read_u32::<LittleEndian>()?;
        let data_check = v.read_u32::<LittleEndian>()?;
        let magic = v.read_u32::<LittleEndian>()?;
        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_check,
            magic,
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.write_u32::<LittleEndian>(self.command)?;
        v.write_u32::<LittleEndian>(self.arg0)?;
        v.write_u32::<LittleEndian>(self.arg1)?;
        v.write_u32::<LittleEndian>(self.data_length)?;
        v.write_u32::<LittleEndian>(self.data_check)?;
        v.write_u32::<LittleEndian>(self.magic)?;
        Ok(v)
    }

    pub fn command(&self) -> &'static str {
        match self.command {
            A_SYNC => "SYNC",
            A_CNXN => "CNXN",
            A_OPEN => "OPEN",
            A_OKAY => "OKAY",
            A_CLSE => "CLSE",
            A_WRTE => "WRTE",
            A_AUTH => "AUTH",
            A_STLS => "STLS",
            _ => panic!(),
        }
    }
}

pub struct APacket {
    pub msg: AMessage,
    pub payload: Vec<u8>,
}

impl APacket {
    pub fn new(command: u32) -> Self {
        let msg = AMessage::new(command);
        APacket {
            msg,
            payload: vec![],
        }
    }
}
