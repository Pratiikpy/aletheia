// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Aletheia's on-chain Ruling Registry — a structured, tamper-evident seal for every "Settle It"
/// verdict on X Layer. Unlike a bare hash anchor, it records the decodable outcome (winner,
/// confidence, agreement, evidence + judge counts) keyed by the sha256 seal of the full debate
/// record, so any party can look a ruling up on-chain and verify it against the cited transcript
/// Aletheia returns. Grounded + debated + judged + sealed: a receipt, not a vote.
contract RulingRegistry {
    struct Ruling {
        bytes32 questionHash; // keccak256 of the disputed question
        uint8 winner;         // 0=A, 1=B, 2=tie, 3=unresolved
        uint8 confidence;     // 0-100
        uint8 agreement;      // 0-100 (share of judges on the majority)
        uint16 sources;       // number of cited evidence sources
        uint16 judges;        // number of judges that voted
        uint64 timestamp;     // seal time
        address sealer;
    }

    address public owner;
    uint256 public total;
    mapping(bytes32 => Ruling) public rulings; // seal (sha256, as bytes32) => Ruling

    event RulingSealed(
        bytes32 indexed seal,
        bytes32 indexed questionHash,
        uint8 winner,
        uint8 confidence,
        uint8 agreement,
        uint16 sources,
        uint16 judges,
        uint64 timestamp,
        address sealer
    );

    constructor() { owner = msg.sender; }

    /// Commit a Settle It ruling on-chain, keyed by the sha256 seal of its full record.
    function sealRuling(
        bytes32 seal,
        bytes32 questionHash,
        uint8 winner,
        uint8 confidence,
        uint8 agreement,
        uint16 sources,
        uint16 judges
    ) external {
        require(rulings[seal].timestamp == 0, "sealed");
        require(winner <= 3 && confidence <= 100 && agreement <= 100, "range");
        rulings[seal] = Ruling(questionHash, winner, confidence, agreement, sources, judges, uint64(block.timestamp), msg.sender);
        total++;
        emit RulingSealed(seal, questionHash, winner, confidence, agreement, sources, judges, uint64(block.timestamp), msg.sender);
    }

    /// Read a sealed ruling back by its seal.
    function get(bytes32 seal) external view returns (Ruling memory) { return rulings[seal]; }
}
