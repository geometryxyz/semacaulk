// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Semacaulk {
    uint8 public immutable LAGRANGE_TREE_LEVELS;
    uint256 public lagrangeTreeRoot;
    uint256 currentIndex;

    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // By setting the value of unset (empty) tree leaves to this
    // nothing-up-my-sleeve value, the authors demonstrate, via the property of
    // second-preimage resistance of Keccak256, that they do not have its
    // preimage and therefore cannot spend funds they do not own.
    uint256 public NOTHING_UP_MY_SLEEVE_ZERO = 
        uint256(keccak256(abi.encodePacked('Semacaulk'))) % SNARK_SCALAR_FIELD;

    constructor(
        uint8 _lagrangeTreeLevels,
        uint256 _lagrangeTreeRoot
    ) {
        LAGRANGE_TREE_LEVELS = _lagrangeTreeLevels;
        lagrangeTreeRoot = _lagrangeTreeRoot;
    }

    function insertIdentity(
        uint256 _identityCommitment,
        bytes32 _lagrangeLeaf,
        bytes32[] memory _lagrangeMerkleProof
    ) public {
        // 1. Verify that _lagrangeLeaf exists in the lagrange tree at index currentIndex
        // 2. Compute delta = (_identityCommitment - NOTHING_UP_MY_SLEEVE) * _lagrangeLeaf
    }

    function broadcastSignal(
    ) public {
    }
}
