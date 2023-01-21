// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import { Types } from "./Types.sol";

contract BN254 {
    // The base field
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // The scalar field
    uint256 constant PRIME_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @return the generator of G1
    // solhint-disable-next-line func-name-mixedcase
    function P1() internal pure returns (Types.G1Point memory) {
        return Types.G1Point(1, 2);
    }

    /// @return the generator of G2
    // solhint-disable-next-line func-name-mixedcase
    function P2() internal pure returns (Types.G2Point memory) {
        return
            Types.G2Point({
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
        } else { return Types.G1Point(_p.x, PRIME_Q - (_p.y % PRIME_Q));
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
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, result, 0x60)
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
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, result, 0x60)
            switch success case 0 { revert(0, 0) }
        }

        require(success, "BN254: plus failed");

        return result;
    }

    /// @dev Evaluate the following pairing product:
    /// @dev e(-a1, a2).e(b1, b2).e(c1, c2) == 1
    /// @dev caller needs to ensure that a1, a2, b1, b2, c1 and c2 are within proper group
    /// @notice credit: Aztec, Spilsbury Holdings Ltd
    function caulkPlusPairing(
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
            mstore(mPtr, mload(a1))
            mstore(add(mPtr, 0x20), mload(add(a1, 0x20)))
            mstore(add(mPtr, 0x40), mload(a2))
            mstore(add(mPtr, 0x60), mload(add(a2, 0x20)))
            mstore(add(mPtr, 0x80), mload(add(a2, 0x40)))
            mstore(add(mPtr, 0xa0), mload(add(a2, 0x60)))

            mstore(add(mPtr, 0xc0), mload(b1))
            mstore(add(mPtr, 0xe0), mload(add(b1, 0x20)))
            mstore(add(mPtr, 0x100), mload(b2))
            mstore(add(mPtr, 0x120), mload(add(b2, 0x20)))
            mstore(add(mPtr, 0x140), mload(add(b2, 0x40)))
            mstore(add(mPtr, 0x160), mload(add(b2, 0x60)))

            mstore(add(mPtr, 0x180), mload(c1))
            mstore(add(mPtr, 0x1a0), mload(add(c1, 0x20)))
            mstore(add(mPtr, 0x1c0), mload(c2))
            mstore(add(mPtr, 0x1e0), mload(add(c2, 0x20)))
            mstore(add(mPtr, 0x200), mload(add(c2, 0x40)))
            mstore(add(mPtr, 0x220), mload(add(c2, 0x60)))

            success := staticcall(gas(), 8, mPtr, 0x240, 0x00, 0x20)
            out := mload(0x00)
        }
        require(success, "Bn254: Pairing check failed!");
        return (out != 0);
    }

    /// @dev Temporary function that invokes pairing check
    function verifyPairingThree(
        uint[2] memory a1,
        uint[2][2] memory a2,
        uint[2] memory b1,
        uint[2][2] memory b2,
        uint[2] memory c1,
        uint[2][2] memory c2
    ) public view returns (bool) {
        Types.G1Point memory A1 = Types.G1Point(a1[0], a1[1]);
        Types.G2Point memory A2 = Types.G2Point(a2[0][0], a2[0][1], a2[1][0], a2[1][1]);

        Types.G1Point memory B1 = Types.G1Point(b1[0], b1[1]);
        Types.G2Point memory B2 = Types.G2Point(b2[0][0], b2[0][1], b2[1][0], b2[1][1]);

        Types.G1Point memory C1 = Types.G1Point(c1[0], c1[1]);
        Types.G2Point memory C2 = Types.G2Point(c2[0][0], c2[0][1], c2[1][0], c2[1][1]);

        return caulkPlusPairing(A1, A2, B1, B2, C1, C2);
    }
}
