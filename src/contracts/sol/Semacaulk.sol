// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { KeccakMT } from "./KeccakMT.sol";

contract Semacaulk is KeccakMT {
    bytes32 public lagrangeTreeRoot;
    uint256 public currentIndex;

    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /*
     * By setting the value of unset (empty) tree leaves to this
     * nothing-up-my-sleeve value, the authors demonstrate, via the property of
     * second-preimage resistance of Keccak256, that they do not have its
     * preimage and therefore cannot spend funds they do not own.
     * To reproduce this value, run the following in a JS console:
     *  e = require('ethers')
     *  (
     *      BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) %
     *          BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
     *  ).toString(16)
     */
    uint256 public NOTHING_UP_MY_SLEEVE_ZERO = 
        uint256(keccak256(abi.encodePacked('Semacaulk'))) % SNARK_SCALAR_FIELD;

    constructor(
        bytes32 _lagrangeTreeRoot
    ) {
        lagrangeTreeRoot = _lagrangeTreeRoot;
    }

    function insertIdentity(
        uint256 _identityCommitment,
        bytes32 _lagrangeLeafX,
        bytes32 _lagrangeLeafY,
        bytes32[] memory _lagrangeMerkleProof
    ) public {
        bytes32 lagrangeLeaf = keccak256(abi.encodePacked(_lagrangeLeafX, _lagrangeLeafY));

        // 1. Verify that _lagrangeLeaf exists in the lagrange tree at index currentIndex
        bytes32 generatedRoot = genRootFromPath(
            currentIndex,
            lagrangeLeaf,
            _lagrangeMerkleProof
        );

        // TODO: use custom errors
        require(generatedRoot == lagrangeTreeRoot, "Semacaulk: Lagrange tree root mismatch");

        // 2. Compute ...

        // Increment the index
        currentIndex += 1;
    }

    function broadcastSignal(
    ) public {
    }
}
