// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract KeccakMT {
    function genRootFromPath(
        uint256 _index,
        bytes32 _leaf,
        bytes32[] memory _proof
    ) public pure returns (bytes32) {
        uint256 r;
        bytes32 levelHash = _leaf;
        for (uint256 i = 0; i < _proof.length; i ++) {
            r = _index % 2;
            _index /= 2;

            if (r == 0) {
                levelHash = hashPair(levelHash, _proof[i]);
            } else {
                levelHash = hashPair(_proof[i], levelHash);
            }
        }
        return levelHash;
    }

    // From openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol
    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
