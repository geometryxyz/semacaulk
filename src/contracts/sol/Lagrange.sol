// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Constants } from "./Constants.sol";

library Lagrange {
    function computeL0Eval(
        uint256 alpha
    ) internal view returns (uint256 result) {
        uint256 p = Constants.PRIME_R;
        //uint256 domainSize = 1024;
        uint256 log2DomainSize = Constants.log2DomainSize;
        uint256 domainSizeInv = Constants.domainSizeInv;

        // Step 1: Compute the evaluation of the vanishing polynomial of the domain with domain_size at
        // alpha
        uint256 vanishingPolyEval = p;
        uint256 d = p;
        if (alpha != 0) {
            assembly {
                vanishingPolyEval := alpha
                // Perform alpha ^ domainSize in a much more efficient manner.
                // Since we know log2(domainSize), we can save a lot of
                // multiplications:
                for {let i := 0} lt(i, log2DomainSize) { i := add(i, 1) } {
                    vanishingPolyEval := mulmod(vanishingPolyEval, vanishingPolyEval, p)
                }

                d := alpha
            }
        }
        vanishingPolyEval = vanishingPolyEval - 1;

        // Step 2: Compute the value 1 / (d - 1)
        uint256 oneDivAlphaMinusOne;
        bool success;
        assembly {
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), sub(d, 1))
            mstore(add(mPtr, 0x80), sub(p, 2))
            mstore(add(mPtr, 0xa0), p)

            // Compute the inverse and store the result to the stack variable
            // oneDivAlphaMinusOne
            success := staticcall(gas(), 5, mPtr, 0xc0, 0x0, 0x20)
            oneDivAlphaMinusOne := mload(oneDivAlphaMinusOne)

            // Just revert
            switch success case 0 { revert(0, 0) }
        }

        // Step 3: Compute the evaluation of the Lagrange polynomial at point alpha
        assembly {
            result := mulmod(
                mulmod(vanishingPolyEval, domainSizeInv, p),
                oneDivAlphaMinusOne,
                p
            )
        }
    }
}
