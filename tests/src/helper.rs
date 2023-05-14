use super::*;

use ckb_testtool::ckb_crypto::secp::Privkey;
use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::packed;
use ckb_testtool::ckb_types::prelude::Builder;
use ckb_testtool::ckb_types::prelude::Entity;
use ckb_testtool::ckb_types::prelude::Pack;
use ckb_testtool::ckb_types::H256;

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    const SIGNATURE_SIZE: usize = 65;
    let _witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = vec![packed::Bytes::default()];
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = packed::WitnessArgs::default();
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
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses[0] = witness
        .as_builder()
        .lock(Some(Bytes::from(sig.serialize())).pack())
        .build()
        .as_bytes()
        .pack();
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
