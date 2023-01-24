// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Verifier } from "../Verifier.sol";
import { Types } from "../Types.sol";

contract TestVerifier is Verifier {
    function testVerifier(
        Types.Proof memory proof,
        Types.G1Point memory accumulator,
        uint256 externalNullifier,
        uint256 nullifierHash
    ) public view {
        verify(proof, accumulator, externalNullifier, nullifierHash);
    }

    function testBatchInvert(
        uint256[8] memory inputs
    ) public view returns (uint256[8] memory) {
        return batchInvert(inputs);
    }
}
