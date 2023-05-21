use crate::error::Error;

pub(crate) const SIGHASH_ALL_SIGNATURE_SIZE: usize = 65;
pub(crate) const MAGIC_CODE: &str = "COTX";

#[derive(PartialEq)]
pub(crate) enum SighashMode {
    All = 0x01,
    None = 0x02,
    Single = 0x03,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
}

impl SighashMode {
    pub fn from_byte(value: u8) -> Result<SighashMode, Error> {
        match value {
            0x01 => Ok(SighashMode::All),
            0x02 => Ok(SighashMode::None),
            0x03 => Ok(SighashMode::Single),
            0x81 => Ok(SighashMode::AllAnyoneCanPay),
            0x82 => Ok(SighashMode::NoneAnyoneCanPay),
            0x83 => Ok(SighashMode::SingleAnyoneCanPay),
            _ => Err(Error::Encoding),
        }
    }
}
