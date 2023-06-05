use crate::helper::{add_prefix, new_blake2b, verify_pubkey_hash};
use crate::types::SIGHASH_ALL_SIGNATURE_SIZE;
use crate::{error::Error, types::SighashMode};

use ckb_lib_secp256k1::LibSecp256k1;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::bytes::Bytes,
    ckb_types::packed::WitnessArgsBuilder,
    ckb_types::prelude::*,
    error::SysError,
    high_level::{load_input, load_transaction, load_witness_args},
};

pub(crate) fn validate_sighash_all_anyonecanpay(
    lib: &LibSecp256k1,
    index: usize,
    signature: &[u8; SIGHASH_ALL_SIGNATURE_SIZE],
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let tx = load_transaction()?.raw();

    // input
    let input = load_input(index, Source::GroupInput)?;
    let input_len = input.as_slice().len() as u64;

    // outputs
    let outputs = tx.outputs();
    let outputs_count = outputs.len();
    let outputs_len = outputs.as_slice().len() as u64;

    // outputs data
    let outputs_data = tx.outputs_data();
    let outputs_data_count = outputs_data.unpack().len() as u64;
    let outputs_data_len = outputs_data.as_slice().len() as u64;

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
    blake2b.update(&outputs_count.to_le_bytes());
    blake2b.update(&outputs_len.to_le_bytes());
    blake2b.update(outputs.as_slice());
    blake2b.update(&outputs_data_count.to_le_bytes());
    blake2b.update(&outputs_data_len.to_le_bytes());
    blake2b.update(outputs_data.as_slice());
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());

    // sighash mode ALL|ANYONECANPAY does not cover witnesses at positions beyond the number of inputs
    let mut i = 0;
    loop {
        if i == index {
            i += 1;
            continue;
        }
        match load_witness_args(i, Source::GroupInput) {
            Ok(_) => {
                let witness = load_witness_args(i, Source::GroupInput)?;
                let witness_for_digest = WitnessArgsBuilder::default()
                    .output_type(witness.output_type())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(Error::LoopGroupInputs),
        }
    }

    blake2b.finalize(&mut message);

    // add prefix
    add_prefix(SighashMode::SingleAnyoneCanPay as u8, &mut message);

    verify_pubkey_hash(lib, &message, signature, expected_pubkey_hash)
}
