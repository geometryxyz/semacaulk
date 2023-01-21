// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Constants {
    // The base field
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // The scalar field
    uint256 constant PRIME_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Compute this value with Fr::from(1024).inverse().unwrap()
    uint256 constant domainSizeInv = 0x3058355F447953C1ADE231A513E0F80710E9DB4E679B02351F90FD168B040001;
    uint256 constant log2DomainSize = 10;
}
