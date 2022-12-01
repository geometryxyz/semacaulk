// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Semacaulk {
    uint8 public immutable LAGRANGE_TREE_LEVELS;
    uint256 public lagrangeTreeRoot;

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
    }

    function broadcastSignal(
    ) public {
    }
}
