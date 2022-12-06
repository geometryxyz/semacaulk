// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract BN254 {
    // The base field
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // The scalar field
    uint256 constant PRIME_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256 x0;
        uint256 x1;
        uint256 y0;
        uint256 y1;
    }

    /// @return the generator of G1
    // solhint-disable-next-line func-name-mixedcase
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// @return the generator of G2
    // solhint-disable-next-line func-name-mixedcase
    function P2() internal pure returns (G2Point memory) {
        return
            G2Point({
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
        G1Point memory _p
    ) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (_p.x == 0 && _p.y == 0) {
            return G1Point(0, 0);
        } else { return G1Point(_p.x, PRIME_Q - (_p.y % PRIME_Q));
        }
    }
    
    /*
     * @return The multiplication of a G1 point with a scalar value.
     */
    function mul(
        G1Point memory _p,
        uint256 v
    ) internal view returns (G1Point memory) {
        uint256[3] memory input;
        input[0] = _p.x;
        input[1] = _p.y;
        input[2] = v;

        G1Point memory result;
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
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory) {

        G1Point memory result;
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
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
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
}
