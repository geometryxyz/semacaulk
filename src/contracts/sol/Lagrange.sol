// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Lagrange {
    function computeL0Eval(
        uint256 alpha
    ) internal view returns (uint256 result) {
        uint256 p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        //uint256 domainSize = 1024;
        uint256 log2DomainSize = 10;
        // Compute this value with Fr::from(domainSize).inverse().unwrap()
        uint256 domainSizeInv = 0x3058355F447953C1ADE231A513E0F80710E9DB4E679B02351F90FD168B040001;

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

        // Step 2: Compute the value 1 / (alpha - 1)
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
            success := staticcall(gas(), 5, mPtr, 0xc0, oneDivAlphaMinusOne, 0x20)
        }

        require(success, "Lagrange: could not invert divisor");

        // Step 3: Compute the evaluation of the Lagrange polynomial at point alpha
        assembly {
            result := mulmod(
                mulmod(vanishingPolyEval , domainSizeInv, p),
                oneDivAlphaMinusOne,
                p
            )
        }
    }
}
