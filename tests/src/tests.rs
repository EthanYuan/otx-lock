use super::*;
use crate::helper::sign_tx;

use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::ckb_crypto::secp::Privkey;
use ckb_testtool::ckb_error::Error;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 10_000_000;

// error numbers
const ERROR_EMPTY_ARGS: i8 = 5;

fn assert_script_error(err: Error, err_code: i8) {
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {} ", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}

fn parepare_key() -> (String, String, [u8; 20]) {
    // random generation
    // address: "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvgs9hktyzvdk4x33phd7pkvyccq6g9tnq4y2d5j"
    // pk: "f8c30a5090d047c2eb4fde48de1034324edda6b1be0d84bbcb8644c5f1e944e0"
    // args: [136, 129, 111, 101, 144, 76, 109, 170, 104, 196, 55, 111, 131, 102, 19, 24, 6, 144, 85, 204]
    ("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvgs9hktyzvdk4x33phd7pkvyccq6g9tnq4y2d5j".to_string(), 
        "f8c30a5090d047c2eb4fde48de1034324edda6b1be0d84bbcb8644c5f1e944e0".to_string(),
        [136, 129, 111, 101, 144, 76, 109, 170, 104, 196, 55, 111, 131, 102, 19, 24, 6, 144, 85, 204])
}

#[test]
fn test_success() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("otx-lock");
    let out_point = context.deploy_cell(contract_bin);

    // build secp cell dep
    let secp256k1_bin = BUNDLED_CELL
        .get("specs/cells/secp256k1_blake160_sighash_all")
        .unwrap();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin.to_vec().into());
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point.clone())
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // generate key
    let (_secp_address, key, args) = parepare_key();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(args.to_vec()))
        .expect("script");

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(secp256k1_dep)
        .cell_dep(secp256k1_data_dep)
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let private_key = Privkey::from_str(&key).unwrap();
    let tx = sign_tx(tx, &private_key);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_empty_args() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("otx-lock");
    let out_point = context.deploy_cell(contract_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Default::default())
        .expect("script");

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, ERROR_EMPTY_ARGS);
}
