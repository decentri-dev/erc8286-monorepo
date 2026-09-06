// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";

import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";
import {CommittedCall} from "./IntentLib.sol";

/// @notice A bound on one ABI argument of the call a frame makes.
///
/// @dev Deliberately ABI-agnostic: the validator knows a selector, a word
///      offset and a bound, never a function signature. `mint(address,uint256)`
///      capped at arg 1 and `addAgent(address)` pinned at arg 0 are the same
///      machinery, so this generalizes to any contract surface rather than the
///      ERC-3643 one the console happens to ship.
///
///      **Static arguments only.** Argument `n` is read from the word at
///      `4 + 32n`, which is the value itself for `address`, `uintN`, `intN`,
///      `bool`, `bytesN` and enums — and an *offset into the tail* for `bytes`,
///      `string`, arrays and structs. A constraint written against a dynamic
///      parameter therefore verifies happily and bounds nothing meaningful.
///      Nothing on chain can detect that: the validator has no ABI. The rule
///      builder holds one and MUST refuse to attach a constraint to a
///      non-static parameter.
struct ArgConstraint {
    /// @dev Zero-based ABI argument position, not a byte offset.
    uint8 argIndex;
    /// @dev One of the `ARG_OP_*` constants.
    uint8 op;
    /// @dev The bound. For `ARG_OP_IN_SET`, a Merkle root over the permitted
    ///      values instead — see {CapabilityLib.valueLeafOf}.
    uint256 operand;
}

/// @notice One `(target, selector)` grant with a native-value ceiling and
///         optional per-argument bounds, either address side optionally
///         wildcarded. The wildcard is its own `scope` field rather than a
///         sentinel address: the unused half of a leaf is then *required* to be
///         zero, so there is nothing a real target or selector can collide with.
/// @dev The leaf encoding is an OpenZeppelin `StandardMerkleTree` over
///      `["uint8","address","bytes4","uint256","bytes32"]`.
struct CapabilityRule {
    uint8 scope;
    address target;
    bytes4 selector;
    /// @dev The most wei one frame under this rule may carry. **Zero forbids
    ///      value entirely**, which is the right default: none of the ERC-3643
    ///      calls a template grants needs ETH, and a `mint` rule that silently
    ///      authorized a transfer of the account's balance would be a hole in
    ///      the layer meant to close them. Unlimited is `type(uint256).max`,
    ///      written out rather than implied.
    ///
    ///      This bounds *one frame*, not a period. A real spend limit needs
    ///      cumulative state, and a VERIFY frame executes under `STATICCALL`
    ///      and can write none — so a transaction with ten frames under the cap
    ///      may move ten times it. ERC-8286 lists spend limits beside target
    ///      restrictions as validation-time policy; this is the honest subset
    ///      of that which the execution context actually permits.
    uint256 maxValue;
    /// @dev `keccak256(abi.encode(ArgConstraint[]))`, or zero for a rule that
    ///      bounds no arguments.
    ///
    ///      A hash rather than the list itself, so the leaf stays a fixed
    ///      five-tuple while the constraints — which are variable-length and
    ///      only needed when the rule is actually exercised — travel in the
    ///      grant. Same shape as {computeRoot} committing to a policy: the
    ///      chain holds the commitment, the caller carries the data.
    bytes32 argsHash;
}

/// @notice One committed frame's authorization: the rule the submitter cites,
///         and the proof that it belongs to the account's policy.
/// @dev Grants are supplied positionally, one per committed frame in frame
///      order. They ride in the VERIFY frame's `data`, which is deliberately
///      NOT committed to the intent digest — so attaching them invalidates no
///      signature, and a proposal signed before a policy landed still
///      broadcasts. The policy is therefore evaluated as it stands at
///      execution time, not at signing time.
struct CapabilityGrant {
    CapabilityRule rule;
    bytes32[] proof;
    /// @dev The rule's argument bounds, which must hash to `rule.argsHash`.
    ///      Empty when the rule constrains nothing.
    ArgConstraint[] constraints;
    /// @dev One membership proof per `ARG_OP_IN_SET` constraint, in the order
    ///      those constraints appear. Empty for a rule with no set bounds.
    bytes32[][] setProofs;
}

/// @title CapabilityLib
/// @notice What an account may ever do, independent of who agrees — the only
///         layer that can refuse a unanimous quorum.
///
/// @dev ## Why this exists
///
///      EIP-8141 has no execution-time enforcement point for `SENDER` frames.
///      Once a VERIFY frame calls `APPROVE` with the execution bit,
///      `sender_approved` is transaction-wide and every subsequent `SENDER`
///      frame runs as `tx.sender` with no further check — no allow-list, no
///      target restriction, no account code in the call path. ERC-8286's
///      Security Considerations therefore make validation-time inspection a
///      MUST for any execution policy. This library is that inspection.
///
///      ## Shape
///
///      A policy is a Merkle root over canonical {CapabilityRule} leaves.
///      Storage is one word; the rules themselves travel in calldata per
///      validation, with a proof. Verification is O(committed frames) over a
///      walk {IntentLib} already performs.
///
///      A zero root means *unrestricted*, matching the console's `UNRESTRICTED`
///      default for an account with no policy row: an account deployed without
///      a policy has exactly the authority its roster gives it, and narrowing
///      that silently would claim a control that does not exist.
///
///      ## Canonical form
///
///      A rule's wildcarded half MUST be zero, and argument bounds MUST sit on
///      a scope that pins the selector. {computeRoot} rejects anything else, so
///      a stored policy is always well-formed and the `CapabilityPolicySet`
///      event always describes a tree that can actually be proven against.
library CapabilityLib {
    /// @dev Exactly this function on exactly this contract.
    uint8 internal constant SCOPE_EXACT = 0;
    /// @dev This function on any contract. The useful direction: it survives
    ///      instruments that do not exist when the policy is written.
    uint8 internal constant SCOPE_ANY_TARGET = 1;
    /// @dev Any function on this contract. Needed by CREATE2 deploy frames,
    ///      whose leading four bytes are a random salt and cannot be enumerated.
    uint8 internal constant SCOPE_ANY_SELECTOR = 2;
    /// @dev Anything at all. Owner accounts only.
    uint8 internal constant SCOPE_ANY = 3;

    /// @dev The argument must equal the operand. Addresses are left-padded in
    ///      their word, so an address bound is just `uint256(uint160(addr))`.
    uint8 internal constant ARG_OP_EQ = 0;
    /// @dev At most the operand — the "up to X" bound.
    uint8 internal constant ARG_OP_LTE = 1;
    /// @dev At least the operand.
    uint8 internal constant ARG_OP_GTE = 2;
    /// @dev The argument must be a member of the set the operand roots.
    ///
    ///      A root rather than a repeated rule because the alternative
    ///      multiplies: fifty permitted recipients across three amount tiers is
    ///      one rule here and a hundred and fifty leaves otherwise, republished
    ///      by the admin every time the list moves.
    uint8 internal constant ARG_OP_IN_SET = 3;

    error EmptyPolicy();
    error UnsortedRules();
    error NonCanonicalRule(uint256 index);

    /// @notice True when every committed call is authorized by the policy.
    /// @param root  The account's `capabilityRoot`; zero means unrestricted.
    /// @param calls The committed calls, as extracted by {IntentLib}.
    /// @param grants One grant per call, positionally matched.
    /// @dev Returns false rather than reverting on any mismatch: a policy
    ///      refusal is a validation failure, and the validator's contract is to
    ///      answer APPROVE_NONE for those.
    function admitsAll(
        IFrameOpcodeAdapter adapter,
        bytes32 root,
        CommittedCall[] memory calls,
        CapabilityGrant[] memory grants
    ) internal view returns (bool) {
        if (root == bytes32(0)) return true;

        // Positional pairing is the whole contract between the two arrays, so a
        // length mismatch is a refusal, never a silent truncation.
        if (grants.length != calls.length) return false;

        for (uint256 i = 0; i < calls.length; i++) {
            if (!covers(grants[i].rule, calls[i])) return false;
            if (!MerkleProofLib.verify(grants[i].proof, root, leafOf(grants[i].rule))) return false;
            if (!argsSatisfied(adapter, grants[i], calls[i])) return false;
        }

        return true;
    }

    /// @notice Whether the call's arguments satisfy the grant's bounds.
    ///
    /// @dev Reads only the arguments a constraint names, so an unconstrained
    ///      rule costs nothing and a constrained one costs one frame read per
    ///      bound — not one per argument in the signature.
    function argsSatisfied(IFrameOpcodeAdapter adapter, CapabilityGrant memory grant, CommittedCall memory call)
        internal
        view
        returns (bool)
    {
        // An unconstrained rule takes no constraints. Extra ones could only ever
        // narrow, so this is about leaving no ambiguity rather than about safety.
        if (grant.rule.argsHash == bytes32(0)) return grant.constraints.length == 0;

        if (keccak256(abi.encode(grant.constraints)) != grant.rule.argsHash) return false;

        uint256 setIndex;

        for (uint256 i = 0; i < grant.constraints.length; i++) {
            ArgConstraint memory constraint = grant.constraints[i];

            // The word for argument n spans [4 + 32n, 36 + 32n). Frame data
            // reads zero-pad past the end, so without this a short-calldata
            // frame would satisfy every upper bound by reading zeros.
            uint256 end = 36 + 32 * uint256(constraint.argIndex);
            if (call.dataLen < end) return false;

            uint256 word = uint256(adapter.frameDataLoad(call.frameIndex, end - 32));

            if (constraint.op == ARG_OP_EQ) {
                if (word != constraint.operand) return false;
            } else if (constraint.op == ARG_OP_LTE) {
                if (word > constraint.operand) return false;
            } else if (constraint.op == ARG_OP_GTE) {
                if (word < constraint.operand) return false;
            } else if (constraint.op == ARG_OP_IN_SET) {
                if (setIndex >= grant.setProofs.length) return false;
                if (!MerkleProofLib.verify(grant.setProofs[setIndex], bytes32(constraint.operand), valueLeafOf(word))) {
                    return false;
                }
                unchecked {
                    setIndex++;
                }
            } else {
                return false; // unknown operator refuses rather than passes
            }
        }

        // Leftover proofs mean the payload does not describe what it verified.
        return setIndex == grant.setProofs.length;
    }

    /// @notice The Merkle leaf for one permitted value in an `ARG_OP_IN_SET`.
    /// @dev `keccak256(keccak256(abi.encode(uint256)))` — an OpenZeppelin
    ///      `StandardMerkleTree` leaf. `abi.encode` left-pads an `address` and a
    ///      `uint256` identically, so a set built off-chain as `["address"]`
    ///      and one built as `["uint256"]` produce the same root, and this one
    ///      function serves both.
    function valueLeafOf(uint256 value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(value))));
    }

    /// @notice Whether one rule authorizes one call.
    /// @dev The zero-checks on the wildcarded half are redundant against a
    ///      policy {computeRoot} accepted, and kept anyway: they make the
    ///      predicate correct on its own terms rather than correct only because
    ///      of what the setter happened to reject.
    ///
    ///      The value ceiling is checked first and applies to every scope,
    ///      including `SCOPE_ANY` — so "may call anything" and "may spend the
    ///      balance" stay separate grants, and an unrestricted rule has to say
    ///      `type(uint256).max` out loud.
    function covers(CapabilityRule memory rule, CommittedCall memory call) internal pure returns (bool) {
        if (call.value > rule.maxValue) return false;

        if (rule.scope == SCOPE_EXACT) {
            return rule.target == call.target && rule.selector == call.selector;
        }
        if (rule.scope == SCOPE_ANY_TARGET) {
            return rule.target == address(0) && rule.selector == call.selector;
        }
        if (rule.scope == SCOPE_ANY_SELECTOR) {
            return rule.selector == bytes4(0) && rule.target == call.target;
        }
        if (rule.scope == SCOPE_ANY) {
            return rule.target == address(0) && rule.selector == bytes4(0);
        }
        return false;
    }

    /// @notice The OpenZeppelin `StandardMerkleTree` leaf for a rule.
    /// @dev `keccak256(keccak256(abi.encode(uint8, address, bytes4, uint256, bytes32)))`.
    ///      `abi.encode` left-pads the `uint8`, `address` and `uint256` and
    ///      right-pads the `bytes4`, exactly as the JS encoder does — so the
    ///      console's `roster.ts` matches by setting its `LEAF_TYPES` to
    ///      `["uint8","address","bytes4","uint256","bytes32"]` and nothing else.
    function leafOf(CapabilityRule memory rule) internal pure returns (bytes32) {
        return keccak256(
            bytes.concat(keccak256(abi.encode(rule.scope, rule.target, rule.selector, rule.maxValue, rule.argsHash)))
        );
    }

    /// @notice Rebuilds the policy's Merkle root from the full rule list.
    ///
    /// @dev Reproduces `StandardMerkleTree.of` over the {leafOf} types: leaves
    ///      are double-hashed, sorted ascending, laid into a `2n-1` array in
    ///      reverse, and parents folded with a sorted-pair hash.
    ///
    ///      Rebuilding rather than trusting a supplied root is what lets
    ///      `CapabilityPolicySet` carry the *complete* rule list authoritatively:
    ///      verifying each rule with its own proof would prove no rule was
    ///      fabricated, but not that none was hidden. Since a VERIFY frame runs
    ///      under `STATICCALL` and can emit nothing, that write-time event is
    ///      the only record an indexer can rely on — so it has to be complete.
    ///
    ///      Callers pass rules pre-sorted by leaf hash; the ascending check is
    ///      O(n) and doubles as the dedupe rule, the same trick `_thresholdMet`
    ///      uses for signer approvals. Runs once per policy change, on a handful
    ///      of rules.
    function computeRoot(CapabilityRule[] calldata rules) internal pure returns (bytes32) {
        uint256 n = rules.length;
        if (n == 0) revert EmptyPolicy();

        bytes32[] memory tree = new bytes32[](2 * n - 1);
        bytes32 previous;

        for (uint256 i = 0; i < n; i++) {
            requireCanonical(rules[i], i);

            bytes32 leaf = leafOf(rules[i]);
            if (i > 0 && leaf <= previous) revert UnsortedRules();
            previous = leaf;

            // OpenZeppelin lays leaves in from the end, in reverse order.
            tree[2 * n - 2 - i] = leaf;
        }

        // Fold parents from the last internal node (n-2) down to the root. The
        // loop counts from n-1 so it never underflows at n == 1, where there is
        // no internal node and the single leaf is already the root.
        for (uint256 i = n - 1; i > 0; i--) {
            uint256 node = i - 1;
            tree[node] = hashPair(tree[2 * node + 1], tree[2 * node + 2]);
        }

        return tree[0];
    }

    /// @notice Reverts unless the wildcarded half of `rule` is zero.
    function requireCanonical(CapabilityRule calldata rule, uint256 index) internal pure {
        bool ok;

        if (rule.scope == SCOPE_EXACT) {
            ok = rule.target != address(0) && rule.selector != bytes4(0);
        } else if (rule.scope == SCOPE_ANY_TARGET) {
            ok = rule.target == address(0) && rule.selector != bytes4(0);
        } else if (rule.scope == SCOPE_ANY_SELECTOR) {
            ok = rule.selector == bytes4(0) && rule.target != address(0);
        } else if (rule.scope == SCOPE_ANY) {
            ok = rule.target == address(0) && rule.selector == bytes4(0);
        }

        // Argument bounds are meaningless without a pinned selector: "argument
        // 1 of anything" names no parameter, since every function numbers its
        // own. Only EXACT and ANY_TARGET fix which function is being described.
        if (ok && rule.argsHash != bytes32(0)) {
            ok = rule.scope == SCOPE_EXACT || rule.scope == SCOPE_ANY_TARGET;
        }

        if (!ok) revert NonCanonicalRule(index);
    }

    /// @dev Commutative node hash, matching OpenZeppelin's `standardNodeHash`
    ///      and Solady's `MerkleProofLib`.
    function hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(bytes.concat(a, b)) : keccak256(bytes.concat(b, a));
    }
}
