// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";

contract BN254 {
    /// @return the generator of G1
    // solhint-disable-next-line func-name-mixedcase
    function P1() internal pure returns (Types.G1Point memory) {
        return Types.G1Point(1, 2);
    }
    
    function P1Neg() internal pure returns (Types.G1Point memory) {
        return Types.G1Point(1, 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45);
    }

    /// @return the generator of G2
    // solhint-disable-next-line func-name-mixedcase
    function P2() internal pure returns (Types.G2Point memory) {
        return Types.G2Point({
            x0: 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
            x1: 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed,
            y0: 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
            y1: 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
        });
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero. 
     */
    function negate(
        Types.G1Point memory _p
    ) internal pure returns (Types.G1Point memory) {
        // The prime q in the base field F_q for G1
        if (_p.x == 0 && _p.y == 0) {
            return Types.G1Point(0, 0);
        } else {
            uint256 q = Constants.PRIME_Q;
            return Types.G1Point(_p.x, q - (_p.y % q));
        }
    }
    
    /*
     * @return The multiplication of a G1 point with a scalar value.
     */
    function mul(
        Types.G1Point memory _p,
        uint256 v
    ) internal view returns (Types.G1Point memory) {
        uint256[3] memory input;
        input[0] = _p.x;
        input[1] = _p.y;
        input[2] = v;

        Types.G1Point memory result;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, result, 0x40)
            switch success case 0 { revert(0, 0) }
        }
        require (success, "BN254: mul failed");

        return result;
    }

    /*
     * @return Returns the sum of two G1 points.
     */
    function plus(
        Types.G1Point memory p1,
        Types.G1Point memory p2
    ) internal view returns (Types.G1Point memory) {

        Types.G1Point memory result;
        bool success;

        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, result, 0x40)
            switch success case 0 { revert(0, 0) }
        }

        require(success, "BN254: plus failed");

        return result;
    }

    // Return true if the following pairing product equals 1:
    // e(-a1, a2) * e(b1, b2) * e(c1, c2) 
    // It is the caller's responsibility to ensure that the points are valid.
    function pairingCheck(
        Types.G1Point memory a1,
        Types.G2Point memory a2,
        Types.G1Point memory b1,
        Types.G2Point memory b2,
        Types.G1Point memory c1,
        Types.G2Point memory c2
    ) internal view returns (bool) {
        uint256 out;
        bool success;
        assembly {
            let mPtr := mload(0x40)
            // a1
            mstore(mPtr, mload(a1))
            mstore(add(mPtr, 0x20), mload(add(a1, 0x20)))
            // a2
            mstore(add(mPtr, 0x40), mload(a2))
            mstore(add(mPtr, 0x60), mload(add(a2, 0x20)))
            mstore(add(mPtr, 0x80), mload(add(a2, 0x40)))
            mstore(add(mPtr, 0xa0), mload(add(a2, 0x60)))
            // b1
            mstore(add(mPtr, 0xc0), mload(b1))
            mstore(add(mPtr, 0xe0), mload(add(b1, 0x20)))
            // b2
            mstore(add(mPtr, 0x100), mload(b2))
            mstore(add(mPtr, 0x120), mload(add(b2, 0x20)))
            mstore(add(mPtr, 0x140), mload(add(b2, 0x40)))
            mstore(add(mPtr, 0x160), mload(add(b2, 0x60)))
            // c1
            mstore(add(mPtr, 0x180), mload(c1))
            mstore(add(mPtr, 0x1a0), mload(add(c1, 0x20)))
            // c2
            mstore(add(mPtr, 0x1c0), mload(c2))
            mstore(add(mPtr, 0x1e0), mload(add(c2, 0x20)))
            mstore(add(mPtr, 0x200), mload(add(c2, 0x40)))
            mstore(add(mPtr, 0x220), mload(add(c2, 0x60)))

            success := staticcall(gas(), 8, mPtr, 0x240, 0x00, 0x20)
            out := mload(0x00)
        }
        require(success, "BN254: pairing check failed!");
        return out == 1;
    }
}
