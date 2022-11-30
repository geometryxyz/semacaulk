// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
//import "./console.sol";
import { KeccakMT } from "../sol/KeccakMT.sol";

contract KeccakMTTest is Test {
    KeccakMT public keccakMt;

    function setUp() public {
        keccakMt = new KeccakMT();
    }

    function testGenRootFromPath() public {
        //r1 = keccak256([0, 0]) = ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5
        //r2 = keccak256([r1, r1]) = b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30
        bytes32 r1 = 0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5;
        bytes32 r2 = 0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30;

        bytes32 leaf = 0x0;
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf;
        proof[1] = r1;

        bytes32 root = keccakMt.genRootFromPath(1, leaf, proof);
        assertEq(root, r2);
    }
}
