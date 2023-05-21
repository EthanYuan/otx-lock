use crate::types::{MAGIC_CODE, SIGHASH_ALL_SIGNATURE_SIZE};
use crate::{error::Error, types::SighashMode};

use ckb_lib_secp256k1::LibSecp256k1;

use blake2b_ref::{Blake2b, Blake2bBuilder};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::string::ToString;
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::bytes::Bytes,
    ckb_types::prelude::*,
    debug,
    high_level::{load_transaction, load_witness_args},
};

pub(crate) fn get_signature_mode_by_witness(
    index: usize,
) -> Result<([u8; SIGHASH_ALL_SIGNATURE_SIZE], SighashMode), Error> {
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

fn add_prefix(sighash: u8, message: &mut [u8]) {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(MAGIC_CODE.as_bytes());
    prefix.push(b' ');
    prefix.extend_from_slice(sighash.to_string().as_bytes());
    prefix.extend_from_slice(b":\n");
    prefix.extend_from_slice(message.len().to_string().as_bytes());
    let new = [prefix, message.to_vec()].concat();

    let mut blake2b = new_blake2b();
    blake2b.update(&new);
    blake2b.finalize(message);
}

pub(crate) fn validate_sighash_single_anyonecanpay(
    lib: &LibSecp256k1,
    index: usize,
    signature: &[u8; SIGHASH_ALL_SIGNATURE_SIZE],
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let tx = load_transaction()?.raw();

    // input
    let input = tx.inputs().get(index).ok_or(Error::Encoding)?;
    let input_len = input.as_slice().len() as u64;

    // output
    let output = tx.outputs().get(index).ok_or(Error::Encoding)?;
    let output_len = output.as_slice().len() as u64;

    // witness
    let witness = load_witness_args(index, Source::GroupInput)?;
    let zero_lock: Bytes = {
        let buf: Vec<_> = vec![0u8; 1 + SIGHASH_ALL_SIGNATURE_SIZE];
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;

    // hash
    let mut message = [0u8; 32];
    let mut blake2b = new_blake2b();
    blake2b.update(&input_len.to_le_bytes());
    blake2b.update(input.as_slice());
    blake2b.update(&output_len.to_le_bytes());
    blake2b.update(output.as_slice());
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    blake2b.finalize(&mut message);

    // add prefix
    add_prefix(SighashMode::SingleAnyoneCanPay as u8, &mut message);

    verify_pubkey_hash(lib, &message, signature, expected_pubkey_hash)
}

fn verify_pubkey_hash(
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
