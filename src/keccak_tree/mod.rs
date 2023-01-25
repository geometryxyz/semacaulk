use ethers::core::utils::keccak256;
use semaphore::merkle_tree::{Hasher, MerkleTree, Proof};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keccak256;

// A Hasher trait for the merkle tree
impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut left_vec: Vec<u8> = Vec::from(left.as_slice());
        let mut right_vec: Vec<u8> = Vec::from(right.as_slice());

        left_vec.append(&mut right_vec);

        keccak256(left_vec)
    }
}

pub type KeccakTree = MerkleTree<Keccak256>;
pub type KeccakMerkleProof = Proof<Keccak256>;
pub type Branch = semaphore::merkle_tree::Branch<Keccak256>;

pub fn flatten_proof(proof: &KeccakMerkleProof) -> Vec<[u8; 32]> {
    let mut result = Vec::with_capacity(proof.0.len());
    for branch in &proof.0 {
        let hash = match branch {
            Branch::Left(hash) => hash,
            Branch::Right(hash) => hash,
        };
        result.push(*hash);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::KeccakTree;
    use ethers::core::utils::hex;

    #[test]
    fn test_keccak_mt() {
        let tree = KeccakTree::new(3, [0; 32]);
        assert_eq!(
            hex::encode(tree.root()),
            "b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30"
        );
    }
}
