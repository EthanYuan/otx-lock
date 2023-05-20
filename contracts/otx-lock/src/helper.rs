use crate::types::SIGHASH_ALL_SIGNATURE_SIZE;
use crate::{error::Error, types::SighashMode};

use ckb_lib_secp256k1::LibSecp256k1;

use blake2b_ref::{Blake2b, Blake2bBuilder};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source, ckb_types::bytes::Bytes, ckb_types::prelude::*, debug,
    high_level::load_witness_args,
};

pub(crate) fn get_signature_mode_by_witness(index: usize) -> Result<(Bytes, SighashMode), Error> {
    let witness_args = load_witness_args(index, Source::GroupInput)?;
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

    Ok((signature.to_vec().into(), SighashMode::from_byte(mode[0])?))
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

pub(crate) fn validate_sighash_single_anyonecanpay(
    _lib: &LibSecp256k1,
    _expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    Ok(())
}
