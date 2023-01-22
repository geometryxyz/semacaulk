// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";

contract Verifier {
    function verify() public view {
    }

    function batchInvert(
        uint256[8] memory inputs
    ) public view returns (uint256[8] memory results) {
        uint256 p = Constants.PRIME_R;
        assembly {
            let mPtr := mload(0x40)
            /*
               0x0   b_1 = inputs[1] * inputs[0]
               0x20  b_2 = inputs[2] * b_1
               0x40  b_3 = inputs[3] * b_2
               0x60  b_4 = inputs[4] * b_3
               0x80  b_5 = inputs[5] * b_4
               0xa0  b_6 = inputs[6] * b_5
               0xc0  b_7 = inputs[7] * b_6
               0xe0      = input to modexp precompile
               0x100     = input to modexp precompile
               0x120     = input to modexp precompile
               0x140     = input to modexp precompile
               0x160     = input to modexp precompile
               0x180     = input to modexp precompile
               0x1a0 t_0 = t_1 * inputs[1] (output)
               0x1c0 t_1 = t_2 * inputs[2]
               0x1e0 t_2 = t_3 * inputs[3]
               0x200 t_3 = t_4 * inputs[4]
               0x220 t_4 = t_5 * inputs[5]
               0x240 t_5 = t_6 * inputs[6]
               0x260 t_6 = t_7 * inputs[7]
               0x280 t_7 = inverse(b_7)
               0x2a0 c_1 = t_1 * b_0 (output)
               0x2c0 c_2 = t_2 * b_1 (output)
               0x2e0 c_3 = t_3 * b_2 (output)
               0x300 c_4 = t_4 * b_3 (output)
               0x320 c_5 = t_5 * b_4 (output)
               0x340 c_6 = t_6 * b_5 (output)
               0x360 c_7 = t_7 * b_6 (output)

               Output t_0, c_1, ..., c_7
             */

            // 1. Compute and store b values
            let a_0 := mload(inputs)
            let a_1 := mload(add(inputs, 0x20))
            let b_1 := mulmod(a_0, a_1, p)
            // Store b_1
            mstore(mPtr, b_1)

            for { let i := 1 } lt(i, 8) { i := add(i, 1) } {
                let offset := mul(i, 0x20)
                let a_i := mload(add(inputs, add(offset, 0x20)))
                let b_i_minus_1 := mload(add(mPtr, sub(offset, 0x20)))
                let b_i := mulmod(a_i, b_i_minus_1, p)
                mstore(add(mPtr, offset), b_i)
            }

            // 2. Compute and store t_7
            mstore(add(mPtr, 0x0e0), 0x20)
            mstore(add(mPtr, 0x100), 0x20)
            mstore(add(mPtr, 0x120), 0x20)
            mstore(add(mPtr, 0x140), mload(add(mPtr, 0xc0)))
            mstore(add(mPtr, 0x160), sub(p, 2))
            mstore(add(mPtr, 0x180), p)
            let success := staticcall(gas(), 0x05, add(mPtr, 0x0e0), 0xc0, add(mPtr, 0x280), 0x20)
            switch success case 0 { revert(0, 0) }

            // 3. Compute and store t_6, .., t_0
            for { let index := 0 } lt(index, 8) { index := add(index, 1) } {
                let i := sub(7, index)
                let a_i := mload(add(inputs, mul(i, 0x20)))
                let offset := add(0x1a0, mul(i, 0x20))
                let t_i_plus_1 := mload(add(mPtr, offset))
                let t_i := mulmod(a_i, t_i_plus_1, p)
                mstore(add(mPtr, sub(offset, 0x20)), t_i)
            }

            // 6. Compute and store c_1
            let c_1 := mulmod(
                mload(add(mPtr, 0x1c0)),
                mload(inputs),
                p
            )
            mstore(add(mPtr, 0x2a0), c_1)

            // 5. Compute and store c_2, ..., c_7
            for { let i := 2 } lt(i, 8) { i := add(i, 1) } {
                let offst := mul(i, 0x20)
                let t_offst := add(0x1a0, offst)
                let b_offst := mul(sub(i, 2), 0x20)

                let t_i := mload(add(mPtr, t_offst))
                let b_i_minus_1 := mload(add(mPtr, b_offst))

                let c_i := mulmod(t_i, b_i_minus_1, p)

                mstore(add(mPtr, add(offst, 0x280)), c_i)
            }

            mstore(    results,        mload(add(mPtr, 0x01a0))) // t0
            mstore(add(results, 0x20), mload(add(mPtr, 0x02a0))) // c1
            mstore(add(results, 0x40), mload(add(mPtr, 0x02c0))) // c2
            mstore(add(results, 0x60), mload(add(mPtr, 0x02e0))) // c3
            mstore(add(results, 0x80), mload(add(mPtr, 0x0300))) // c4
            mstore(add(results, 0xa0), mload(add(mPtr, 0x0320))) // c5
            mstore(add(results, 0xc0), mload(add(mPtr, 0x0340))) // c6
            mstore(add(results, 0xe0), mload(add(mPtr, 0x0360))) // c7
        }
    }
}
