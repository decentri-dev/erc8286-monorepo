// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";

import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";

/// @notice A WebAuthn assertion backing one P-256 entry of `tx.signatures`.
///         The assertion's challenge must be the base64url-encoded intent
///         digest, which is how a passkey signature binds to the intent.
struct PasskeyAssertion {
    /// @dev Byte offset of the `"challenge":"` field within `clientDataJSON`.
    uint256 challengeIndex;
    /// @dev Byte offset of the `"type":"webauthn.get"` field within `clientDataJSON`.
    uint256 typeIndex;
    /// @dev Raw WebAuthn authenticator data.
    bytes authenticatorData;
    /// @dev Raw WebAuthn client data JSON.
    bytes clientDataJSON;
}

/// @notice The call one committed frame makes, in the form a capability policy
///         checks. Extracted during the digest walk, which already reads the
///         resolved target, so only the selector costs an extra introspection.
/// @dev A frame carrying fewer than four bytes of data is not an ABI call — a
///      bare value transfer, or the raw `salt ‖ initCode` of a CREATE2 deploy
///      frame. It still has a target, so it still needs a rule; its selector is
///      zero. This mirrors `committedCalls` in the console's
///      `authz/requirements.ts`, and the two MUST agree: if they disagree about
///      what a deploy frame asks for, the console and the chain disagree about
///      what a policy admits.
struct CommittedCall {
    address target;
    bytes4 selector;
    /// @dev Wei the frame carries. Free to collect: the digest commits `value`
    ///      already, so this is the same read rather than a second one.
    uint256 value;
    /// @dev Where this call sits in `tx.frames`, so a capability rule can read
    ///      the arguments it bounds without walking the frames a second time.
    uint256 frameIndex;
    /// @dev Length of the frame's calldata, for bounds-checking argument reads:
    ///      frame data zero-pads past its end, so an unchecked read of a
    ///      missing argument would satisfy every upper bound.
    uint256 dataLen;
}

/// @title IntentLib
/// @notice Shared "light hash" intent scheme for ERC-8286 validators on the
///         Hegotá devnet: a gas-independent intent digest, an EIP-8250 keyed
///         nonce lane derived from it, and the signature-binding rules.
///
/// @dev ## Intent digest (the light hash)
///
///      Signers approve pure intent: the digest commits no *rate* fields
///      (`max_fee_per_gas`, priority fee, blob fee), so a relayer can still
///      re-price a signed proposal at submission time. It does commit a ceiling
///      on the resulting bill — see "Cost cap" below. Everything
///      execution-relevant IS committed. Byte layout (all words are 32 bytes,
///      big-endian / left-padded; mirror this exactly in off-chain tooling):
///
///      ```
///      INTENT_DOMAIN                        keccak256("erc8286.v1.intent")
///      chainid
///      account                              the ERC-8286 account (== tx.sender)
///      salt                                 backend-chosen unique proposal id
///      maxCost                              wei the account may be charged
///      committedFrameCount                  number of committed frames
///      per committed frame, in tx order:
///        resolvedTarget
///        gasLimit                           committed: prevents starved-gas griefing
///        mode
///        flags                              committed: preserves atomic batching
///        value
///        dataLen
///        keccak256(frameData)               present only when dataLen > 0
///      ```
///
///      Committed frames are those with mode DEFAULT (0) or SENDER (2).
///      VERIFY (1) and POST_TX (3) frames are deliberately NOT committed: the
///      relayer may add validation frames (expiry, its paymaster `pay` frame)
///      and read-only assertion frames later. Safety of the exclusion:
///      - an added VERIFY/POST_TX frame cannot change committed execution;
///      - an added POST_TX frame can only veto the whole transaction;
///      - an added VERIFY frame cannot split an atomic batch: a committed
///        frame carrying the atomic-batch flag must be immediately followed
///        by the next committed frame (enforced during the digest walk);
///      - any added DEFAULT/SENDER frame lands in the digest and breaks it.
///
///      `salt` MUST be unique per proposal: lanes are single-use, so two
///      proposals with identical actions and salts would share a lane and the
///      second could never execute.
///
///      ## Cost cap
///
///      The digest commits `maxCost`: a ceiling in wei on `TXPARAM(0x06)`, the
///      amount `APPROVE_PAYMENT` actually collects. Without a committed fee
///      field of some kind, a relayer granted payment could inflate
///      `max_fee_per_gas` and drain the account up to the committed frame gas
///      limits.
///
///      A ceiling on the bill rather than on the rate, because that is the
///      number a signer can reason about ("this may cost the account at most
///      0.01 ETH") and the one the account is exposed to. The relayer keeps
///      full freedom to re-price under it, so a proposal signed on Monday still
///      broadcasts on Friday at Friday's gas.
///
///      - `maxCost == 0` — the account pays nothing. The payment bit is always
///        cleared, so the transaction needs a sponsor's `pay` frame. This is
///        the right default for a console that relays on its users' behalf.
///      - `maxCost == type(uint256).max` — uncapped, which should be a
///        deliberate choice rather than a default.
///
///      The cap gates only payment. Execution approval is unaffected, so an
///      over-priced transaction fails with the payer unset rather than looking
///      like a validation failure.
///
///      ## Lane binding (EIP-8250)
///
///      Each intent runs on its own keyed-nonce lane:
///
///      ```
///      laneKey = keccak256(LANE_DOMAIN || intentDigest)
///      require nonce_keys == [laneKey] && nonce_seq == 0
///      ```
///
///      Requiring exactly one key stops a crafted transaction from consuming
///      other proposals' lanes alongside its own; requiring seq == 0 makes a
///      lane single-use, so an included bundle can never be replayed at a
///      higher sequence.
///
///      ## Signature binding
///
///      - Passkey (P256 scheme): the protocol verified the P-256 signature
///        over sha256(authenticatorData || sha256(clientDataJSON)); binding is
///        proven by the assertion's challenge being base64url(intentDigest).
///      - EOA (SECP256K1 scheme): the signature entry's explicit 32-byte `msg`
///        must equal the intent digest. A canonical-hash entry (`msg == 0`) is
///        also accepted: it commits to this exact transaction, a strictly
///        stronger statement than the intent.
library IntentLib {
    bytes32 internal constant INTENT_DOMAIN = keccak256("erc8286.v1.intent");
    bytes32 internal constant LANE_DOMAIN = keccak256("erc8286.v1.lane");

    uint256 internal constant TX_PARAM_NONCE_SEQ = 0x01;
    uint256 internal constant TX_PARAM_SENDER = 0x02;

    /// @dev `max cost`: the wei `APPROVE_PAYMENT` collects from the payer —
    ///      all gas at `max_fee_per_gas`, plus blob, intrinsic and signature
    ///      verification costs. The single number the account is actually
    ///      exposed to, which is why the cap is expressed against it rather
    ///      than against `max_fee_per_gas` (`0x04`).
    ///
    ///      ⚠ The Hegotá devnet's TXPARAM map diverges from the EIP-8141 draft
    ///      in the nonce and extension range (`0x01`, `0x0C`, `0x0D`–`0x10`).
    ///      `0x02`, `0x09` and `0x0B` match, and the fee slots are believed
    ///      unchanged, but this one has NOT been read on a live node. Verify it
    ///      before relying on the cap: if the devnet returns something small
    ///      here, the cap silently never binds. A wrong-but-large value fails
    ///      loudly instead, since payment would always be refused.
    uint256 internal constant TX_PARAM_MAX_COST = 0x06;

    uint256 internal constant TX_PARAM_FRAME_COUNT = 0x09;
    uint256 internal constant TX_PARAM_SIG_COUNT = 0x0b;

    uint256 internal constant FRAME_PARAM_RESOLVED_TARGET = 0x00;
    uint256 internal constant FRAME_PARAM_GAS_LIMIT = 0x01;
    uint256 internal constant FRAME_PARAM_MODE = 0x02;
    uint256 internal constant FRAME_PARAM_FLAGS = 0x03;
    uint256 internal constant FRAME_PARAM_DATA_LEN = 0x04;
    uint256 internal constant FRAME_PARAM_VALUE = 0x08;

    uint256 internal constant SIG_PARAM_SIGNER = 0x00;
    uint256 internal constant SIG_PARAM_SCHEME = 0x01;
    uint256 internal constant SIG_PARAM_MSG = 0x02;

    /// @dev EIP-8141 scheme numbering, as the node reports it through
    ///      `SIGPARAM(i, SIG_PARAM_SCHEME)`. `0` is ARBITRARY — no protocol
    ///      crypto and no resolved signer — so no approval can ever carry it.
    uint256 internal constant SCHEME_SECP256K1 = 0x1;
    uint256 internal constant SCHEME_P256 = 0x2;

    uint256 internal constant MODE_DEFAULT = 0;
    uint256 internal constant MODE_VERIFY = 1;
    uint256 internal constant MODE_SENDER = 2;
    uint256 internal constant MODE_POST_TX = 3;

    uint256 internal constant ATOMIC_BATCH_FLAG = 0x04;

    /// @dev WebAuthn clientDataJSON literals and masks for word-compare
    ///      matching, left-aligned in a word.
    bytes32 internal constant CLIENT_TYPE_LITERAL = '"type":"webauthn.get"'; // 21 bytes
    bytes32 internal constant CLIENT_CHALLENGE_LITERAL = '"challenge":"'; // 13 bytes
    bytes32 internal constant MASK_TOP_21 = bytes32(~(type(uint256).max >> 168));
    bytes32 internal constant MASK_TOP_13 = bytes32(~(type(uint256).max >> 104));
    bytes32 internal constant MASK_TOP_11 = bytes32(~(type(uint256).max >> 88));

    /// @notice Builds the intent digest from transaction introspection, and
    ///         extracts the call each committed frame makes.
    /// @return ok False when the frame list is not a valid intent carrier:
    ///         an unknown frame mode, or an uncommitted frame splitting an
    ///         atomic batch of committed frames.
    /// @return digest The light-hash intent digest (valid only when `ok`).
    /// @return calls One entry per committed frame, in frame order — what a
    ///         capability policy must admit. Collected here rather than in a
    ///         second walk: the resolved target is read either way, so the whole
    ///         marginal cost is one `frameDataLoad` per frame that carries
    ///         calldata. A second walk would repeat the mode and length reads
    ///         too, and adapter call framing, not computation, is what this loop
    ///         actually spends.
    function buildIntentDigest(IFrameOpcodeAdapter adapter, address account, bytes32 salt, uint256 maxCost)
        internal
        view
        returns (bool ok, bytes32 digest, CommittedCall[] memory calls)
    {
        uint256 frameCount = adapter.txParam(TX_PARAM_FRAME_COUNT);

        bytes memory frameBlob;
        uint256 committedCount;
        bool pendingAtomic; // the previous committed frame carried the atomic flag

        // Sized to the upper bound, then truncated below: memory arrays cannot
        // grow, and the committed count is only known after the walk.
        calls = new CommittedCall[](frameCount);

        for (uint256 i = 0; i < frameCount; i++) {
            uint256 mode = adapter.frameParam(i, FRAME_PARAM_MODE);

            if (mode == MODE_VERIFY || mode == MODE_POST_TX) {
                // An inserted frame between an atomic-flagged committed frame
                // and its successor would split the batch and break its
                // all-or-nothing semantics.
                if (pendingAtomic) return (false, bytes32(0), calls);
                continue;
            }
            if (mode != MODE_DEFAULT && mode != MODE_SENDER) return (false, bytes32(0), calls);

            (bytes memory segment, bool atomic) = _committedFrame(adapter, i, mode, calls, committedCount);

            frameBlob = bytes.concat(frameBlob, segment);
            pendingAtomic = atomic;
            committedCount++;
        }

        // Shrink to the committed frames. Safe: `committedCount` never exceeds
        // the allocated length, and only the length word is rewritten.
        assembly ("memory-safe") {
            mstore(calls, committedCount)
        }

        digest = keccak256(
            bytes.concat(
                INTENT_DOMAIN,
                bytes32(block.chainid),
                bytes32(uint256(uint160(account))),
                salt,
                bytes32(maxCost),
                bytes32(committedCount),
                frameBlob
            )
        );
        return (true, digest, calls);
    }

    /// @notice True when the transaction's `max cost` is within the ceiling the
    ///         signers committed to.
    /// @dev Read only when the payment bit is otherwise grantable; a sponsored
    ///      transaction charges the account nothing, so gating it on the bill
    ///      would refuse legitimate re-pricing for no benefit.
    function costWithinCap(IFrameOpcodeAdapter adapter, uint256 maxCost) internal view returns (bool) {
        if (maxCost == type(uint256).max) return true;
        return adapter.txParam(TX_PARAM_MAX_COST) <= maxCost;
    }

    /// @dev One committed frame's contribution to the digest — its six words
    ///      plus, when it carries data, the data hash — together with the call
    ///      it makes and whether it opens an atomic batch.
    ///
    ///      Kept separate from the walk, and writing the call into `calls[slot]`
    ///      rather than returning it, because the two together sit right at the
    ///      EVM's reachable stack limit.
    function _committedFrame(
        IFrameOpcodeAdapter adapter,
        uint256 frameIndex,
        uint256 mode,
        CommittedCall[] memory calls,
        uint256 slot
    ) private view returns (bytes memory segment, bool atomic) {
        uint256 flags = adapter.frameParam(frameIndex, FRAME_PARAM_FLAGS);
        uint256 dataLen = adapter.frameParam(frameIndex, FRAME_PARAM_DATA_LEN);
        uint256 target = adapter.frameParam(frameIndex, FRAME_PARAM_RESOLVED_TARGET);
        uint256 value = adapter.frameParam(frameIndex, FRAME_PARAM_VALUE);

        // Only frames carrying a full selector are read: for anything shorter
        // the selector is zero, which is what the console's `committedCalls`
        // records too, and skipping the load saves an adapter round-trip on
        // every CREATE2 deploy frame.
        calls[slot] = CommittedCall({
            target: address(uint160(target)),
            selector: dataLen >= 4 ? bytes4(adapter.frameDataLoad(frameIndex, 0)) : bytes4(0),
            value: value,
            frameIndex: frameIndex,
            dataLen: dataLen
        });
        atomic = (flags & ATOMIC_BATCH_FLAG) != 0;

        segment = abi.encode(target, adapter.frameParam(frameIndex, FRAME_PARAM_GAS_LIMIT), mode, flags, value, dataLen);
        if (dataLen > 0) segment = bytes.concat(segment, adapter.frameDataHash(frameIndex));
    }

    /// @notice The EIP-8250 nonce key (lane) assigned to an intent.
    function laneKey(bytes32 intentDigest) internal pure returns (uint256) {
        return uint256(keccak256(bytes.concat(LANE_DOMAIN, intentDigest)));
    }

    /// @notice True when the transaction runs on exactly the intent's lane:
    ///         a single nonce key equal to `laneKey(digest)` at sequence 0.
    function laneMatches(IFrameOpcodeAdapter adapter, bytes32 intentDigest) internal view returns (bool) {
        if (adapter.nonceKeyCount() != 1) return false;
        if (adapter.nonceKey(0) != laneKey(intentDigest)) return false;
        if (adapter.txParam(TX_PARAM_NONCE_SEQ) != 0) return false;
        return true;
    }

    /// @notice True when the SECP256K1 signature entry at `sigIndex` binds the
    ///         intent: explicit `msg == intentDigest`, or `msg == 0` (a
    ///         canonical-transaction-hash signature, strictly stronger).
    function eoaBindsIntent(IFrameOpcodeAdapter adapter, uint256 sigIndex, bytes32 intentDigest)
        internal
        view
        returns (bool)
    {
        uint256 msgValue = adapter.sigParam(sigIndex, SIG_PARAM_MSG);
        return msgValue == uint256(intentDigest) || msgValue == 0;
    }

    /// @notice True when the P256 signature entry at `sigIndex` is a WebAuthn
    ///         assertion over exactly this intent digest.
    /// @dev The protocol already verified the P-256 signature over
    ///      sha256(authenticatorData || sha256(clientDataJSON)) and attributed
    ///      it to `SIGPARAM(sigIndex, signer)`; this proves the assertion's
    ///      challenge is the intent digest and the reported `msg` matches the
    ///      assertion. Bounds-safe: returns false instead of reverting.
    function passkeyBindsIntent(
        IFrameOpcodeAdapter adapter,
        uint256 sigIndex,
        PasskeyAssertion memory assertion,
        bytes32 intentDigest
    ) internal view returns (bool) {
        if (assertion.authenticatorData.length < 37) return false;

        if (!checkClientDataShape(
                assertion.clientDataJSON, assertion.challengeIndex, assertion.typeIndex, base64UrlEncode32(intentDigest)
            )) {
            return false;
        }

        bytes32 clientHash = sha256(assertion.clientDataJSON);
        bytes32 msgHash = sha256(abi.encodePacked(assertion.authenticatorData, clientHash));

        return adapter.sigParam(sigIndex, SIG_PARAM_MSG) == uint256(msgHash);
    }

    /// @notice Roster leaf for an effective signer address. Matches
    ///         OpenZeppelin's StandardMerkleTree with an `["address"]` leaf
    ///         encoding, so backends can use the openzeppelin/merkle-tree JS
    ///         library off the shelf.
    function leafOf(address effectiveSigner) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(effectiveSigner))));
    }

    /// @notice Verifies a sorted-pair (commutative) Merkle proof that
    ///         `effectiveSigner` is a member of `root`.
    /// @dev Solady's MerkleProofLib hashes sorted pairs in scratch space and
    ///      is OpenZeppelin-compatible, so the roster tooling is unchanged.
    function verifyMembership(bytes32[] memory proof, bytes32 root, address effectiveSigner)
        internal
        pure
        returns (bool)
    {
        return MerkleProofLib.verify(proof, root, leafOf(effectiveSigner));
    }

    /// @dev Checks the WebAuthn `clientDataJSON` is a `webauthn.get` asserting
    ///      exactly `expectedChallengeB64` (43 base64url chars) as its
    ///      challenge. Bounds-safe: returns false instead of reverting.
    ///
    ///      Matching uses masked word-compares instead of per-byte loops. The
    ///      masked mloads may read past the end of `clientData`; that is
    ///      harmless because the out-of-range bytes are masked off before
    ///      comparison and nothing is written.
    function checkClientDataShape(
        bytes memory clientData,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes memory expectedChallengeB64
    ) internal pure returns (bool ok) {
        uint256 clientLen = clientData.length;

        if (typeIndex == type(uint256).max || typeIndex + 22 > clientLen) return false;
        if (challengeIndex == type(uint256).max || challengeIndex + 57 > clientLen) return false;
        if (expectedChallengeB64.length != 43) return false;

        bytes32 typeLit = CLIENT_TYPE_LITERAL;
        bytes32 challengeLit = CLIENT_CHALLENGE_LITERAL;
        bytes32 mask21 = MASK_TOP_21;
        bytes32 mask13 = MASK_TOP_13;
        bytes32 mask11 = MASK_TOP_11;
        assembly {
            let data := add(clientData, 32)
            // "type":"webauthn.get" at typeIndex (21 bytes).
            ok := eq(and(mload(add(data, typeIndex)), mask21), typeLit)
            // "challenge":" at challengeIndex (13 bytes).
            ok := and(ok, eq(and(mload(add(data, challengeIndex)), mask13), challengeLit))
            // The 43-byte challenge right after the marker: 32 raw + 11 masked.
            let want := add(expectedChallengeB64, 32)
            let got := add(data, add(challengeIndex, 13))
            ok := and(ok, eq(mload(got), mload(want)))
            ok := and(ok, eq(and(mload(add(got, 32)), mask11), and(mload(add(want, 32)), mask11)))
            // Closing quote after the challenge.
            ok := and(ok, eq(byte(0, mload(add(data, add(challengeIndex, 56)))), 0x22))
        }
    }

    /// @dev base64url encoding of a 32-byte value (43 chars, no padding).
    ///
    ///      Specialized assembly encoder: the input is a stack word, so no
    ///      out-of-bounds reads are possible and the tail character is
    ///      computed from masked bits only — the output is deterministic
    ///      whatever the prior memory state. (Solady 0.0.156's Base64.encode
    ///      is NOT safe here: it reads past the input buffer and leaks two
    ///      dirty bits into the 43rd character when `len % 3 == 2`.)
    ///
    ///      The character table is staged in scratch space offset to 0x1f so
    ///      that `mload(c)`'s lowest byte is table entry `c`; the free memory
    ///      pointer is cached and restored around the table write.
    function base64UrlEncode32(bytes32 input) internal pure returns (bytes memory out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := mload(0x40)

            // Table at [0x1f..0x5f): entry c lands at 0x1f + c, and
            // mload(c)'s lowest byte is memory[c + 31] == memory[c + 0x1f].
            // This temporarily overwrites the free memory pointer slot.
            mstore(0x1f, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
            mstore(0x3f, "ghijklmnopqrstuvwxyz0123456789-_")

            let ptr := add(out, 0x20)
            // Ten full 3-byte groups: input bytes [0..30) -> chars [0..40).
            for { let i := 0 } lt(i, 30) { i := add(i, 3) } {
                let chunk := shr(232, shl(mul(8, i), input))
                mstore8(ptr, mload(and(shr(18, chunk), 0x3F)))
                mstore8(add(ptr, 1), mload(and(shr(12, chunk), 0x3F)))
                mstore8(add(ptr, 2), mload(and(shr(6, chunk), 0x3F)))
                mstore8(add(ptr, 3), mload(and(chunk, 0x3F)))
                ptr := add(ptr, 4)
            }
            // Tail: input bytes 30,31 -> chars 40,41,42; the last character's
            // two low bits are zero per RFC 4648.
            mstore(ptr, 0) // pre-zero so the bytes after char 42 are clean
            let tail := and(input, 0xffff)
            mstore8(ptr, mload(and(shr(10, tail), 0x3F)))
            mstore8(add(ptr, 1), mload(and(shr(4, tail), 0x3F)))
            mstore8(add(ptr, 2), mload(and(shl(2, tail), 0x3F)))

            mstore(out, 43)
            mstore(0x40, add(out, 0x60)) // restore FMP: 0x20 header + 43 -> 0x40
        }
    }
}
