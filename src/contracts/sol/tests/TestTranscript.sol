// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TranscriptLibrary } from "../Transcript.sol";
import { Types } from "../Types.sol";

contract TestTranscript {
    function testChallenges(
        uint256 u1,
        uint256 u2,
        Types.G1Point memory pt1,
        Types.G2Point memory pt2
    ) public pure returns(uint256, uint256) {
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.newTranscript();

        TranscriptLibrary.updateWithU256(transcript, u1);

        TranscriptLibrary.updateWithG1(transcript, pt1);

        uint256 challenge_1 =  TranscriptLibrary.getChallenge(transcript);

        TranscriptLibrary.updateWithU256(transcript, u2);
        TranscriptLibrary.updateWithG2(transcript, pt2);

        uint256 challenge_2 =  TranscriptLibrary.getChallenge(transcript);

        return (challenge_1, challenge_2);
    }

}
