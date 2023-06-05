use crate::types::{MAGIC_CODE, SIGHASH_ALL_SIGNATURE_SIZE};
use crate::{error::Error, types::SighashMode};

use ckb_lib_secp256k1::LibSecp256k1;

use blake2b_ref::{Blake2b, Blake2bBuilder};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::string::ToString;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source, ckb_types::bytes::Bytes, ckb_types::prelude::*, debug,
    high_level::load_witness_args,
};

pub(crate) fn get_signature_mode_by_witness(
    index: usize,
) -> Result<([u8; SIGHASH_ALL_SIGNATURE_SIZE], SighashMode), Error> {
    let witness_args = load_witness_args(index, Source::Input)?;
    let witness_lock: Bytes = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::Encoding)?
        .unpack();
    if witness_lock.len() != SIGHASH_ALL_SIGNATURE_SIZE + 1 {
        return Err(Error::Encoding);
    }
    let mut mode = [0u8; 1];
    let mut signature = [0u8; SIGHASH_ALL_SIGNATURE_SIZE];
    mode.copy_from_slice(&witness_lock[..1]);
    signature.copy_from_slice(&witness_lock[1..1 + SIGHASH_ALL_SIGNATURE_SIZE]);

    Ok((signature, SighashMode::from_byte(mode[0])?))
}

pub(crate) fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build()
}

pub(crate) fn validate_secp256k1_blake2b_sighash_all(
    lib: &LibSecp256k1,
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    lib.validate_blake2b_sighash_all(&mut pubkey_hash)
        .map_err(|err_code| {
            debug!("secp256k1 error {}", err_code);
            Error::Secp256k1
        })?;

    // compare with expected pubkey_hash
    if &pubkey_hash[..] != expected_pubkey_hash {
        return Err(Error::WrongPubkey);
    }
    Ok(())
}

pub(crate) fn add_prefix(sighash: u8, message: &mut [u8]) {
    let mut blake2b = new_blake2b();
    blake2b.update(MAGIC_CODE.as_bytes());
    blake2b.update(b" ");
    blake2b.update(sighash.to_string().as_bytes());
    blake2b.update(b":\n");
    blake2b.update(message.len().to_string().as_bytes());
    blake2b.update(message);
    blake2b.finalize(message);
}

pub(crate) fn verify_pubkey_hash(
    lib: &LibSecp256k1,
    message: &[u8],
    signature: &[u8; SIGHASH_ALL_SIGNATURE_SIZE],
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let prefilled_data = lib.load_prefilled_data().map_err(|err| {
        debug!("load prefilled data error: {}", err);
        Error::LoadPrefilledData
    })?;
    let pubkey = lib
        .recover_pubkey(&prefilled_data, signature, &message)
        .map_err(|err| {
            debug!("recover pubkey error: {}", err);
            Error::RecoverPubkey
        })?;
    let pubkey_hash = {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(pubkey.as_slice());
        hasher.finalize(&mut buf);
        buf
    };
    if &expected_pubkey_hash[..] != &pubkey_hash[..20] {
        return Err(Error::WrongPubkey);
    }
    Ok(())
}
