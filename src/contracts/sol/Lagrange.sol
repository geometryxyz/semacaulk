// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Constants } from "./Constants.sol";

library Lagrange {
    function computeL0AndVanishingEval(
        uint256 alpha,
        uint256 dMinusOneInv,
        uint256 log2DomainSize,
        uint256 domainSizeInv
    ) internal pure returns (uint256 result, uint256 vanishingPolyEval) {
        uint256 p = Constants.PRIME_R;

        // Step 1: Compute the evaluation of the vanishing polynomial of the domain with domain_size at
        // alpha
        vanishingPolyEval = p;
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

        // Step 2: Check that dMinusOneInv = 1 / (d - 1)
        assembly {
            let r := mulmod(sub(d, 1), dMinusOneInv, p)
            switch r case 1 {} default { revert(0, 0) }
        }

        // Step 3: Compute the evaluation of the Lagrange polynomial at point alpha
        assembly {
            result := mulmod(
                mulmod(vanishingPolyEval, domainSizeInv, p),
                dMinusOneInv,
                p
            )
        }
    }
}
