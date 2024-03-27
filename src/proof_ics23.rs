use ics23::{ExistenceProof, HashOp, InnerOp, InnerSpec, LeafOp, LengthOp, ProofSpec};

use crate::sha256::Sha256Hasher;
use crate::{collections::VecDeque, MerkleProof, H256};

pub fn convert(merkle_proof: MerkleProof, key: &H256, value: &H256) -> ExistenceProof {
    let (leaves_bitmap, proof) = merkle_proof.take();
    let merge_height_bitmap = leaves_bitmap.first().expect("The heights should exist");
    let mut proof: VecDeque<_> = proof.into();
    let mut cur_key = *key;
    let mut height = 0;
    let mut path = Vec::new();
    while !proof.is_empty() {
        // check the height is valid
        if merge_height_bitmap.get_bit(height) {
            let sibling = proof.pop_front().expect("no proof").hash::<Sha256Hasher>();
            let inner_op = get_inner_op(&sibling, cur_key.is_right(height));
            path.push(inner_op);
        }

        if height == core::u8::MAX {
            break;
        }
        cur_key = cur_key.parent_path(height);
        height += 1;
    }

    ExistenceProof {
        key: key.as_slice().to_vec(),
        value: value.as_slice().to_vec(),
        leaf: Some(get_leaf_op()),
        path,
    }
}

fn get_leaf_op() -> LeafOp {
    LeafOp {
        hash: HashOp::Sha256.into(),
        prehash_key: HashOp::NoHash.into(),
        prehash_value: HashOp::NoHash.into(),
        length: LengthOp::NoPrefix.into(),
        prefix: H256::zero().as_slice().to_vec(),
    }
}

fn get_inner_op(sibling: &H256, is_right_node: bool) -> InnerOp {
    let node = sibling.as_slice().to_vec();
    let (prefix, suffix) = if is_right_node {
        (node, vec![])
    } else {
        (vec![], node)
    };
    InnerOp {
        hash: HashOp::Sha256.into(),
        prefix,
        suffix,
    }
}

pub fn get_spec() -> ProofSpec {
    ProofSpec {
        leaf_spec: Some(get_leaf_op()),
        inner_spec: Some(get_inner_spec()),
        max_depth: core::u8::MAX as i32,
        min_depth: 0,
        prehash_key_before_comparison: true,
    }
}

fn get_inner_spec() -> InnerSpec {
    InnerSpec {
        child_order: vec![0, 1],
        child_size: 32,
        min_prefix_length: 0,
        max_prefix_length: 32,
        empty_child: vec![],
        hash: HashOp::Sha256.into(),
    }
}
