use crate::error::Error;
use crate::helper::{
    get_signature_mode_by_witness, validate_secp256k1_blake2b_sighash_all,
    validate_sighash_all_anyonecanpay, validate_sighash_single_anyonecanpay,
};
use crate::types::{SighashMode, SIGHASH_ALL_SIGNATURE_SIZE};

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    dynamic_loading_c_impl::CKBDLContext,
    high_level::{load_script, load_transaction, load_witness_args},
};

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
    let inputs_count = load_transaction()?.raw().inputs().len();
    for i in 0..inputs_count {
        // switch case
        let (signature, sighash_mode) = get_signature_mode_by_witness(i)?;
        return match sighash_mode {
            SighashMode::All => Err(Error::UnsupportedSighashMode),
            SighashMode::None => Err(Error::UnsupportedSighashMode),
            SighashMode::Single => Err(Error::UnsupportedSighashMode),
            SighashMode::AllAnyoneCanPay => {
                validate_sighash_all_anyonecanpay(&lib, i, &signature, &args)
            }
            SighashMode::NoneAnyoneCanPay => Err(Error::UnsupportedSighashMode),
            SighashMode::SingleAnyoneCanPay => {
                validate_sighash_single_anyonecanpay(&lib, i, &signature, &args)
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
