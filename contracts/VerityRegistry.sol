// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Verity's on-chain proof-of-correctness ledger. Every verdict is committed BEFORE the outcome is
/// known (timestamped, immutable), then graded later — a publicly auditable accuracy record on X Layer.
contract VerityRegistry {
    struct Attestation {
        address subject;   // token/contract the verdict is about
        uint8 verdict;     // 0=GO, 1=CAUTION, 2=AVOID
        uint8 score;       // 0-100
        uint8 confidence;  // 0-100
        uint64 timestamp;  // commit time (pre-outcome)
        bool graded;
        bool correct;
    }

    address public owner;
    uint256 public total;
    uint256 public graded;
    uint256 public correct;
    mapping(bytes32 => Attestation) public attestations;

    event Committed(bytes32 indexed id, address indexed subject, uint8 verdict, uint8 score, uint64 timestamp);
    event Graded(bytes32 indexed id, bool correct);

    constructor() { owner = msg.sender; }

    /// Commit a verdict on-chain before the outcome is known.
    function commit(bytes32 id, address subject, uint8 verdict, uint8 score, uint8 confidence) external {
        require(attestations[id].timestamp == 0, "exists");
        require(verdict <= 2 && score <= 100 && confidence <= 100, "range");
        attestations[id] = Attestation(subject, verdict, score, confidence, uint64(block.timestamp), false, false);
        total++;
        emit Committed(id, subject, verdict, score, uint64(block.timestamp));
    }

    /// Grade a prior commitment once the outcome is known (did the AVOID actually rug, etc.).
    function grade(bytes32 id, bool wasCorrect) external {
        require(msg.sender == owner, "only owner");
        Attestation storage a = attestations[id];
        require(a.timestamp != 0 && !a.graded, "bad");
        a.graded = true;
        a.correct = wasCorrect;
        graded++;
        if (wasCorrect) correct++;
        emit Graded(id, wasCorrect);
    }

    /// Live accuracy in basis points (correct/graded * 10000).
    function accuracyBps() external view returns (uint256) {
        return graded == 0 ? 0 : (correct * 10000) / graded;
    }
}
