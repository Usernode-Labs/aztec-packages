use acir::circuit::{Circuit, Program};
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir_field::FieldElement;
use aztec_barretenberg_rs::{
    batch_merge, batch_merge_agg_vk, batch_merge_from_leaf_merges_with_vk, batch_merge_leaf_vk,
    batch_merge_leaf_with_vk, mega_honk_circuit_metadata, mega_honk_public_inputs,
    mega_honk_vk_hash, prove_mega_honk, verify_batch_merge, verify_batch_merge_leaf,
    verify_mega_honk_leaf,
};
use serde::Serialize;

const FORMAT_MSGPACK_COMPACT: u8 = 3;

fn serialize_msgpack_compact<T: Serialize>(value: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    value
        .serialize(
            &mut rmp_serde::Serializer::new(&mut payload)
                .with_bytes(rmp_serde::config::BytesMode::ForceAll),
        )
        .expect("serialize msgpack-compact payload");
    let mut bytes = Vec::with_capacity(payload.len() + 1);
    bytes.push(FORMAT_MSGPACK_COMPACT);
    bytes.extend(payload);
    bytes
}

#[test]
fn proves_and_verifies_beta_22_acir() {
    let circuit = Circuit::from_str(
        r#"
        private parameters: [w1, w2]
        public parameters: []
        return values: [w3]
        ASSERT 0 = w1 + w2 - w3
        "#,
    )
    .expect("parse addition circuit");
    let program = Program {
        functions: vec![circuit],
        unconstrained_functions: Vec::new(),
    };
    let acir = serialize_msgpack_compact(&program);

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(1), FieldElement::from(2u128));
    witness_map.insert(Witness(2), FieldElement::from(3u128));
    witness_map.insert(Witness(3), FieldElement::from(5u128));
    let witness = serialize_msgpack_compact(&WitnessStack::from(witness_map));

    let metadata = mega_honk_circuit_metadata(&acir).expect("read circuit metadata");
    assert_eq!(
        metadata.num_public_inputs, 9,
        "one semantic input plus DefaultIO"
    );

    let (proof, vk) = prove_mega_honk(&acir, &witness).expect("prove beta.22 ACIR");
    assert!(
        verify_mega_honk_leaf(&proof.0, &vk.0).expect("verify proof"),
        "fresh proof must verify"
    );
    assert_ne!(mega_honk_vk_hash(&vk.0).expect("hash VK"), [0u8; 32]);

    let public_inputs = mega_honk_public_inputs(&proof.0, &vk.0).expect("extract public inputs");
    assert_eq!(public_inputs.len(), 32);
    let mut expected = [0u8; 32];
    expected[31] = 5;
    assert_eq!(public_inputs, expected);
}

#[test]
fn bb5_embedded_batch_merge_keys_match_generated_circuits() {
    let circuit = Circuit::from_str(
        r#"
        private parameters: [w1, w2, w3, w4, w5]
        public parameters: []
        return values: [w1, w2, w3, w4, w5]
        "#,
    )
    .expect("parse five-input leaf circuit");
    let program = Program {
        functions: vec![circuit],
        unconstrained_functions: Vec::new(),
    };
    let acir = serialize_msgpack_compact(&program);

    let mut witness_map = WitnessMap::new();
    for index in 1..=5 {
        witness_map.insert(Witness(index), FieldElement::from(index as u128));
    }
    let witness = serialize_msgpack_compact(&WitnessStack::from(witness_map));
    let (leaf_proof, leaf_vk) = prove_mega_honk(&acir, &witness).expect("prove leaf circuit");

    let (leaf_merge_proof, generated_leaf_merge_vk) =
        batch_merge_leaf_with_vk(&leaf_proof.0, &leaf_vk.0, &leaf_proof.0, &leaf_vk.0)
            .expect("merge leaf proofs");
    assert_eq!(
        generated_leaf_merge_vk.0,
        batch_merge_leaf_vk()
            .expect("read embedded leaf merge VK")
            .0,
        "embedded leaf merge VK must match the BB5 circuit"
    );
    assert!(
        verify_batch_merge_leaf(&leaf_merge_proof.0).expect("verify leaf merge proof"),
        "leaf merge proof must verify with the embedded BB5 key"
    );

    let (agg_merge_proof, generated_agg_merge_vk) =
        batch_merge_from_leaf_merges_with_vk(&leaf_merge_proof.0, &leaf_merge_proof.0)
            .expect("merge level-one proofs");
    assert_eq!(
        generated_agg_merge_vk.0,
        batch_merge_agg_vk()
            .expect("read embedded aggregate merge VK")
            .0,
        "embedded aggregate merge VK must match the BB5 circuit"
    );
    assert!(
        verify_batch_merge(&agg_merge_proof.0).expect("verify aggregate merge proof"),
        "aggregate merge proof must verify with the embedded BB5 key"
    );

    let deeper_merge = batch_merge(&agg_merge_proof.0, &agg_merge_proof.0)
        .expect("merge aggregate proofs at the next depth");
    assert!(
        verify_batch_merge(&deeper_merge.0).expect("verify deeper aggregate proof"),
        "deeper merge proof must keep using the stable aggregate BB5 key"
    );
}
