use ckb_testtool::ckb_crypto::secp::Privkey;
use ckb_testtool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, *},
    prelude::*,
    H256,
};

pub const MAX_CYCLES: u64 = 10_000_000;
pub const SIGNATURE_SIZE: usize = 65;
pub const MAGIC_CODE: &str = "COTX";

pub enum SighashMode {
    All = 0x01,
    None = 0x02,
    Single = 0x03,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
}

pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

pub fn sign_secp256k1_blake2b_sighash_all(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn add_prefix(sighash: u8, message: &mut [u8]) {
    let prefix = format!("{} {}:\n{}", MAGIC_CODE, sighash, message.len())
        .as_bytes()
        .to_vec();
    let new = [prefix, message.to_vec()].concat();

    let mut blake2b = new_blake2b();
    blake2b.update(&new);
    blake2b.finalize(message);
}

pub fn sign_sighash_single_acp(
    tx: TransactionView,
    key: &Privkey,
    input_index: usize,
) -> TransactionView {
    // input
    let input = tx.inputs().get(input_index).unwrap();
    let input_len = input.as_slice().len() as u64;

    // output
    let output = tx.outputs().get(input_index).unwrap();
    let output_len = output.as_slice().len() as u64;

    // witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(1 + SIGNATURE_SIZE, 0);
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

    // sign
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");

    // witness
    let mut witness_lock = vec![SighashMode::SingleAnyoneCanPay as u8];
    witness_lock.extend_from_slice(&sig.serialize());
    let witness = witness
        .as_builder()
        .lock(Some(Bytes::from(witness_lock)).pack())
        .build()
        .as_bytes()
        .pack();

    // set witness
    tx.as_advanced_builder().witness(witness).build()
}

pub fn sign_sighash_all_acp(
    tx: TransactionView,
    key: &Privkey,
    input_index: usize,
) -> TransactionView {
    // input
    let input = tx.inputs().get(input_index).unwrap();
    let input_len = input.as_slice().len() as u64;

    // outputs
    let outputs = tx.outputs();
    let outputs_count = outputs.len();
    let outputs_len = outputs.as_slice().len() as u64;

    // witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(1 + SIGNATURE_SIZE, 0);
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
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());

    for i in 0..tx.inputs().len() {
        if i == input_index {
            continue;
        }
        let witness_for_digest = WitnessArgsBuilder::default().build();
        let witness_len = witness_for_digest.as_bytes().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness_for_digest.as_bytes());
    }

    blake2b.finalize(&mut message);

    // add prefix
    add_prefix(SighashMode::SingleAnyoneCanPay as u8, &mut message);

    // sign
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");

    // witness
    let mut witness_lock = vec![SighashMode::AllAnyoneCanPay as u8];
    witness_lock.extend_from_slice(&sig.serialize());
    let witness = witness
        .as_builder()
        .lock(Some(Bytes::from(witness_lock)).pack())
        .build()
        .as_bytes()
        .pack();

    // set witness
    tx.as_advanced_builder().witness(witness).build()
}
