// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract KeccakMT {
    function verifyMerklePath(
        //uint256 _index,
        //bytes32[] memory _proof
    ) public pure returns (bytes32) {
        return bytes32(0x0);
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
