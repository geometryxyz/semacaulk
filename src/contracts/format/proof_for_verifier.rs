use crate::bn_solidity_utils::f_to_u256;
use crate::multiopen::MultiopenProof as RustMultiopenProof;
use crate::prover::{Commitments as RustCommitments, Openings as RustOpenings, Proof as RustProof};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ethers::prelude::abigen;

abigen!(Verifier, "./src/contracts/out/Verifier.sol/Verifier.json");

pub type ProofForVerifier = Proof;

pub fn g1_affine_to_g1point(pt: &G1Affine) -> G1Point {
    G1Point {
        x: f_to_u256(pt.x),
        y: f_to_u256(pt.y),
    }
}

pub fn g2_affine_to_g2point(pt: &G2Affine) -> G2Point {
    G2Point {
        x_0: f_to_u256(pt.x.c1),
        x_1: f_to_u256(pt.x.c0),
        y_0: f_to_u256(pt.y.c1),
        y_1: f_to_u256(pt.y.c0),
    }
}

pub fn format_multiopen_proof(multiopen_proof: &RustMultiopenProof<Bn254>) -> MultiopenProof {
    MultiopenProof {
        q_1_opening: f_to_u256(multiopen_proof.q1_opening),
        q_2_opening: f_to_u256(multiopen_proof.q2_opening),
        q_3_opening: f_to_u256(multiopen_proof.q3_opening),
        q_4_opening: f_to_u256(multiopen_proof.q4_opening),
        f_cm: g1_affine_to_g1point(&multiopen_proof.f_cm),
        final_poly_proof: g1_affine_to_g1point(&multiopen_proof.final_poly_proof),
    }
}

pub fn format_commitments(commitments: &RustCommitments<Bn254>) -> Commitments {
    Commitments {
        w_0: g1_affine_to_g1point(&commitments.w0),
        w_1: g1_affine_to_g1point(&commitments.w1),
        w_2: g1_affine_to_g1point(&commitments.w2),
        key: g1_affine_to_g1point(&commitments.key),
        c: g1_affine_to_g1point(&commitments.c),
        quotient: g1_affine_to_g1point(&commitments.quotient),
        u_prime: g1_affine_to_g1point(&commitments.u_prime),
        zi: g1_affine_to_g1point(&commitments.zi),
        ci: g1_affine_to_g1point(&commitments.ci),
        p_1: g1_affine_to_g1point(&commitments.p1),
        p_2: g1_affine_to_g1point(&commitments.p2),
        q_mimc: g1_affine_to_g1point(&commitments.q_mimc),
        h: g1_affine_to_g1point(&commitments.h),
        w: g2_affine_to_g2point(&commitments.w),
    }
}

pub fn format_openings(openings: &RustOpenings<Bn254>) -> Openings {
    Openings {
        q_mimc: f_to_u256(openings.q_mimc),
        c: f_to_u256(openings.c),
        quotient: f_to_u256(openings.quotient),
        u_prime: f_to_u256(openings.u_prime),
        p_1: f_to_u256(openings.p1),
        p_2: f_to_u256(openings.p2),
        w_0_0: f_to_u256(openings.w0_0),
        w_0_1: f_to_u256(openings.w0_1),
        w_0_2: f_to_u256(openings.w0_2),
        w_1_0: f_to_u256(openings.w1_0),
        w_1_1: f_to_u256(openings.w1_1),
        w_1_2: f_to_u256(openings.w1_2),
        w_2_0: f_to_u256(openings.w2_0),
        w_2_1: f_to_u256(openings.w2_1),
        w_2_2: f_to_u256(openings.w2_2),
        key_0: f_to_u256(openings.key_0),
        key_1: f_to_u256(openings.key_1),
    }
}

pub fn format_proof(proof: &RustProof<Bn254>) -> Proof {
    Proof {
        multiopen_proof: format_multiopen_proof(&proof.multiopen_proof),
        commitments: format_commitments(&proof.commitments),
        openings: format_openings(&proof.openings),
    }
}
