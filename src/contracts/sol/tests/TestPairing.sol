// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Verifier } from "../Verifier.sol";
import { Types } from "../Types.sol";

contract TestPairing is Verifier {
    function testPairing(
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

        return pairingCheck(A1, A2, B1, B2, C1, C2);
    }
}
