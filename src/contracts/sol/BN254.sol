// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract BN254 {
    // The order of G1 and G2 in the BN254 curve
    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero. 
     */
    function negate(
        G1Point memory _p
    ) internal pure returns (G1Point memory) {
        uint256 PRIME_Q =
            21888242871839275222246405745257275088696311157297823662689037894645226208583;

        // The prime q in the base field F_q for G1
        if (_p.x == 0 && _p.y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(_p.x, PRIME_Q - (_p.y % PRIME_Q));
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
            switch success case 0 { invalid() }
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
            switch success case 0 { invalid() }
        }

        require(success, "BN254: plus failed");

        return result;
    }
}
