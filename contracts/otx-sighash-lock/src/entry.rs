use crate::error::Error;
use crate::helper::{get_signature_mode_by_witness, validate_secp256k1_blake2b_sighash_all};
use crate::types::{SighashMode, SIGHASH_ALL_SIGNATURE_SIZE};
use crate::validate::{validate_sighash_all_anyonecanpay, validate_sighash_single_anyonecanpay};

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    dynamic_loading_c_impl::CKBDLContext,
    high_level::{
        load_cell_lock_hash, load_script, load_script_hash, load_witness_args, QueryIter,
    },
};

use alloc::vec::Vec;
use ckb_lib_secp256k1::LibSecp256k1;

pub fn main() -> Result<(), Error> {
    // load script
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::ItemMissing);
    }

    // create a DL context with 128K buffer size
    let mut context: CKBDLContext<[u8; 128 * 1024]> = unsafe { CKBDLContext::new() };
    let lib = LibSecp256k1::load(&mut context);

    // This lock script is fully compatible with the secp256k1_blake2b_sighash_all signature algorithm.
    // In this compatible mode, other witnesses in the same lock script group do not need to be verified.
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness_lock: Bytes = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::Encoding)?
        .unpack();
    if witness_lock.len() == SIGHASH_ALL_SIGNATURE_SIZE {
        return validate_secp256k1_blake2b_sighash_all(&lib, &args);
    }

    // This is a lock script that is compatible with various sighash modes,
    // so we need to verify each witness in the same lock script group
    let current_script_hash = load_script_hash()?;
    let group_inputs_absolute_indices: Vec<_> = QueryIter::new(load_cell_lock_hash, Source::Input)
        .enumerate()
        .filter_map(|(i, hash)| {
            if hash == current_script_hash {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    for i in group_inputs_absolute_indices.iter() {
        let (signature, sighash_mode) = get_signature_mode_by_witness(*i)?;
        match sighash_mode {
            SighashMode::All => return Err(Error::UnsupportedSighashMode),
            SighashMode::None => return Err(Error::UnsupportedSighashMode),
            SighashMode::Single => return Err(Error::UnsupportedSighashMode),
            SighashMode::AllAnyoneCanPay => {
                validate_sighash_all_anyonecanpay(
                    &lib,
                    *i,
                    &group_inputs_absolute_indices,
                    &signature,
                    &args,
                )?;
            }
            SighashMode::NoneAnyoneCanPay => return Err(Error::UnsupportedSighashMode),
            SighashMode::SingleAnyoneCanPay => {
                validate_sighash_single_anyonecanpay(&lib, *i, &signature, &args)?;
            }
        };
    }

    Ok(())
}

// Unit tests are supported.
#[test]
fn test_foo() {
    assert!(true);
}
