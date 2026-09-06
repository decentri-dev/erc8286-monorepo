// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {ArgConstraint, CapabilityGrant, CapabilityLib, CapabilityRule} from "../src/erc8286/v1/CapabilityLib.sol";
import {IFrameOpcodeAdapter} from "../src/erc8286/v1/IFrameOpcodeAdapter.sol";
import {CommittedCall} from "../src/erc8286/v1/IntentLib.sol";
import {MockFrameAdapterV1} from "./MultiSignerFrameValidatorV1.t.sol";

/// @dev Exposes the library's internals for direct assertions.
contract CapabilityHarness {
    function root(CapabilityRule[] calldata rules) external pure returns (bytes32) {
        return CapabilityLib.computeRoot(rules);
    }

    function leaf(CapabilityRule calldata rule) external pure returns (bytes32) {
        return CapabilityLib.leafOf(rule);
    }

    function covers(CapabilityRule calldata rule, CommittedCall calldata call) external pure returns (bool) {
        return CapabilityLib.covers(rule, call);
    }

    function admitsAll(
        IFrameOpcodeAdapter adapter,
        bytes32 policyRoot,
        CommittedCall[] calldata calls,
        CapabilityGrant[] calldata grants
    ) external view returns (bool) {
        return CapabilityLib.admitsAll(adapter, policyRoot, calls, grants);
    }
}

/// @title CapabilityV1Test
/// @notice The contract side of the capability layer, checked against fixtures
///         produced by OpenZeppelin's merkle-tree package — the same library,
///         leaf encoding and tree construction the operator console's
///         `capability` module uses.
///
/// @dev These roots are the point of the file. The console computes the root a
///      validator will read, so if the two encodings ever diverge, every
///      proposal an account makes starts failing at validation with no other
///      signal. A hand-written Solidity tree that merely agrees with itself
///      would catch none of that.
///
///      A v1 leaf is five fields — `(uint8 scope, address target, bytes4
///      selector, uint256 maxValue, bytes32 argsHash)` — and the console encodes
///      exactly those, in that order, in the SDK's `capability.ts`.
///
///      The template roots below are asserted from the other side too, in
///      `apps/web/lib/api/authz/capability/encoding.test.ts`. Both files must
///      move together: a template edit that lands in only one of them leaves the
///      pair green against each other and wrong against the chain.
contract CapabilityV1Test is Test {
    CapabilityHarness harness;
    MockFrameAdapterV1 mock;

    uint8 constant EXACT = 0;
    uint8 constant ANY_TARGET = 1;
    uint8 constant ANY_SELECTOR = 2;
    uint8 constant ANY = 3;

    uint256 constant NO_VALUE = 0;
    uint256 constant UNLIMITED = type(uint256).max;
    bytes32 constant NO_ARGS = bytes32(0);

    // Selectors, as the console derives them from the ERC-3643 v4.2 ABIs.
    bytes4 constant MINT = 0x40c10f19;
    bytes4 constant BURN = 0x9dc29fac;
    bytes4 constant TRANSFER = 0xa9059cbb;
    bytes4 constant PAUSE = 0x8456cb59;
    bytes4 constant UNPAUSE = 0x3f4ba83a;
    bytes4 constant FORCED_TRANSFER = 0x9fc1d0e7;
    bytes4 constant SET_ADDRESS_FROZEN = 0xc69c09cf;
    bytes4 constant FREEZE_PARTIAL = 0x125c4a33;
    bytes4 constant UNFREEZE_PARTIAL = 0x1fe56f7d;
    bytes4 constant ADD_MODULE = 0x1ed86f19;
    bytes4 constant REMOVE_MODULE = 0xa0632461;
    bytes4 constant CALL_MODULE_FUNCTION = 0xefb22d33;
    bytes4 constant ADD_CLAIM = 0xb1a34e0d;
    bytes4 constant REGISTER_IDENTITY = 0x454a03e0;

    address constant CREATE2_DEPLOYER = 0xeEd646DC7594ca540CfbA8910adAd07ad96197b6;
    address constant TOKEN = 0x00000000000000000000000000000000000bEEf1;

    bytes32 constant ROOT_OWNER = 0xe129b37c5c00fe721695819caffa82b69b04228fe5d6691135af440dd2c91148;
    bytes32 constant ROOT_TREASURY = 0x0b494202ee5de0633e24d867d633e61d34c490f7933296804d4b8779f8e84833;
    bytes32 constant ROOT_TRANSFER_AGENT = 0x7a5f6385c63059df6e262752f2676ddb14bf22d36bd9513ed4f94f700a7c0512;
    bytes32 constant ROOT_COMPLIANCE = 0x7bf2ef32807b0220443f34fc97c9623526f5ae3f83fd806dd6c93e53bbc096a6;

    /// @dev A two-rule mint/burn policy, and the proofs for its two leaves.
    ///
    ///      Deliberately *not* the Treasury template. The tests below use this to
    ///      exercise the validator — forged rules, raised ceilings, mismatched
    ///      grant counts — and want a tree small enough that a proof is a single
    ///      node. Pinning them to a catalog entry instead made every edit to that
    ///      entry rewrite proofs that were never testing the catalog, which is
    ///      how the Treasury fixture came to disagree with the console.
    bytes32 constant ROOT_MINT_BURN = 0xc3562f14b4f50df52c3e36ddec7d98ff091541e2c575489620fc18796ee321f6;
    bytes32 constant PROOF_MINT = 0x9c54cc56e5a42ca880ad701c6a5d06609bc37ff2153a7d320c51979fdce12ad9;
    bytes32 constant PROOF_BURN = 0x49be163131c5273356d7ce256de6b9d6d49f6a48366be220ed2b0359a37d3d13;

    function setUp() public {
        harness = new CapabilityHarness();
        mock = new MockFrameAdapterV1();
    }

    /* ------------------------------- builders ------------------------------ */

    function _rule(uint8 scope, address target, bytes4 selector, uint256 maxValue)
        internal
        pure
        returns (CapabilityRule memory)
    {
        return _rule(scope, target, selector, maxValue, NO_ARGS);
    }

    function _rule(uint8 scope, address target, bytes4 selector, uint256 maxValue, bytes32 argsHash)
        internal
        pure
        returns (CapabilityRule memory)
    {
        return
            CapabilityRule({scope: scope, target: target, selector: selector, maxValue: maxValue, argsHash: argsHash});
    }

    function _call(address target, bytes4 selector) internal pure returns (CommittedCall memory) {
        return _call(target, selector, 0);
    }

    /// @dev `dataLen` is a two-argument call; these tests bound no arguments, so
    ///      nothing reads it.
    function _call(address target, bytes4 selector, uint256 value) internal pure returns (CommittedCall memory) {
        return CommittedCall({target: target, selector: selector, value: value, frameIndex: 0, dataLen: 68});
    }

    /// @dev The templates, with rules in the ascending-leaf order the setter
    ///      requires. The console's declaration order differs; OpenZeppelin
    ///      sorts internally, so the SDK sorts before calling.
    ///
    ///      Every ERC-3643 grant carries `NO_VALUE`: none of these calls is
    ///      payable, so a rule permitting ETH alongside them would widen the
    ///      policy for nothing.
    function _owner() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](1);
        rules[0] = _rule(ANY, address(0), bytes4(0), UNLIMITED);
    }

    /// @dev The policy behind {ROOT_MINT_BURN}, not a catalog template.
    function _mintBurn() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](2);
        rules[0] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), BURN, NO_VALUE);
    }

    function _treasury() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](3);
        rules[0] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), FORCED_TRANSFER, NO_VALUE);
        rules[2] = _rule(ANY_TARGET, address(0), BURN, NO_VALUE);
    }

    function _transferAgent() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](6);
        rules[0] = _rule(ANY_TARGET, address(0), UNFREEZE_PARTIAL, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), UNPAUSE, NO_VALUE);
        rules[2] = _rule(ANY_TARGET, address(0), FORCED_TRANSFER, NO_VALUE);
        rules[3] = _rule(ANY_TARGET, address(0), FREEZE_PARTIAL, NO_VALUE);
        rules[4] = _rule(ANY_TARGET, address(0), PAUSE, NO_VALUE);
        rules[5] = _rule(ANY_TARGET, address(0), SET_ADDRESS_FROZEN, NO_VALUE);
    }

    function _compliance() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](6);
        rules[0] = _rule(ANY_TARGET, address(0), REMOVE_MODULE, NO_VALUE);
        rules[1] = _rule(ANY_SELECTOR, CREATE2_DEPLOYER, bytes4(0), NO_VALUE);
        rules[2] = _rule(ANY_TARGET, address(0), ADD_CLAIM, NO_VALUE);
        rules[3] = _rule(ANY_TARGET, address(0), CALL_MODULE_FUNCTION, NO_VALUE);
        rules[4] = _rule(ANY_TARGET, address(0), ADD_MODULE, NO_VALUE);
        rules[5] = _rule(ANY_TARGET, address(0), REGISTER_IDENTITY, NO_VALUE);
    }

    /* ------------------- cross-check against the JS encoder ---------------- */

    function test_rootsMatchEncoder_owner() public view {
        assertEq(harness.root(_owner()), ROOT_OWNER);
    }

    function test_rootsMatchEncoder_treasury() public view {
        assertEq(harness.root(_treasury()), ROOT_TREASURY);
    }

    function test_rootsMatchEncoder_transferAgent() public view {
        assertEq(harness.root(_transferAgent()), ROOT_TRANSFER_AGENT);
    }

    function test_rootsMatchEncoder_mintBurn() public view {
        assertEq(harness.root(_mintBurn()), ROOT_MINT_BURN);
    }

    /// @dev Six rules: an odd, non-power-of-two tree, where OpenZeppelin's
    ///      reverse leaf placement and unbalanced folding actually differ from
    ///      a naive pairwise build. The template that would break first.
    function test_rootsMatchEncoder_compliance() public view {
        assertEq(harness.root(_compliance()), ROOT_COMPLIANCE);
    }

    /// @dev A single-rule policy has no internal nodes: the leaf *is* the root.
    function test_singleRuleRootIsItsLeaf() public view {
        assertEq(harness.root(_owner()), harness.leaf(_rule(ANY, address(0), bytes4(0), UNLIMITED)));
    }

    function test_encoderProofsVerify_mintBurn() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = PROOF_MINT;

        assertTrue(_admits(ROOT_MINT_BURN, _call(TOKEN, MINT), _rule(ANY_TARGET, address(0), MINT, NO_VALUE), proof));
    }

    /// @dev Depth 3 out of the ragged six-leaf tree.
    function test_encoderProofsVerify_complianceAddClaim() public view {
        bytes32[] memory proof = new bytes32[](3);
        proof[0] = 0xbbd06978c835eb0ca3fb643c03a2bf4680967c47f5afd331ecc317dbc28610f6;
        proof[1] = 0x0b3d04cfc1ffc691dc25f1211b0a3946f7a0258835a8d4018dce3912c0126a3c;
        proof[2] = 0x66ae91c2f9274e10d05e5cdcc6f22d329bb7913f7cd347ac40d16d149c696920;

        assertTrue(
            _admits(ROOT_COMPLIANCE, _call(TOKEN, ADD_CLAIM), _rule(ANY_TARGET, address(0), ADD_CLAIM, NO_VALUE), proof)
        );
    }

    /// @dev The CREATE2 deploy rule, proven against the same six-leaf tree. Its call carries a random salt
    ///      rather than a selector, which is why the rule is any-selector.
    function test_encoderProofsVerify_complianceDeployer() public view {
        bytes32[] memory proof = new bytes32[](3);
        proof[0] = 0x0edafe1f3756f16817d2c4b2d9b287822039a49ef565da0269317a3fea8b174b;
        proof[1] = 0x2a3a52f4c027167088d03ba4290ba9e287a0e52f9167ccbdd03c306aabc7da77;
        proof[2] = 0x66ae91c2f9274e10d05e5cdcc6f22d329bb7913f7cd347ac40d16d149c696920;

        assertTrue(
            _admits(
                ROOT_COMPLIANCE,
                _call(CREATE2_DEPLOYER, bytes4(0)),
                _rule(ANY_SELECTOR, CREATE2_DEPLOYER, bytes4(0), NO_VALUE),
                proof
            )
        );
    }

    /* ------------------------------ scopes -------------------------------- */

    function test_anyTargetAdmitsAnyInstrument() public view {
        CapabilityRule memory rule = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT)));
        assertTrue(harness.covers(rule, _call(address(0xDEAD), MINT)));
        assertFalse(harness.covers(rule, _call(TOKEN, BURN)));
    }

    function test_exactRequiresBothHalves() public view {
        CapabilityRule memory rule = _rule(EXACT, TOKEN, MINT, NO_VALUE);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT)));
        assertFalse(harness.covers(rule, _call(address(0xDEAD), MINT)));
        assertFalse(harness.covers(rule, _call(TOKEN, BURN)));
    }

    function test_anySelectorIsPerTarget() public view {
        CapabilityRule memory rule = _rule(ANY_SELECTOR, CREATE2_DEPLOYER, bytes4(0), NO_VALUE);
        assertTrue(harness.covers(rule, _call(CREATE2_DEPLOYER, bytes4(0))));
        assertTrue(harness.covers(rule, _call(CREATE2_DEPLOYER, MINT)));
        assertFalse(harness.covers(rule, _call(TOKEN, MINT)));
    }

    function test_anyCoversEverything() public view {
        CapabilityRule memory rule = _rule(ANY, address(0), bytes4(0), UNLIMITED);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT)));
        assertTrue(harness.covers(rule, _call(CREATE2_DEPLOYER, bytes4(0))));
    }

    function test_nonCanonicalRuleCoversNothing() public view {
        assertFalse(harness.covers(_rule(ANY_TARGET, TOKEN, MINT, NO_VALUE), _call(TOKEN, MINT)));
        assertFalse(harness.covers(_rule(ANY_SELECTOR, TOKEN, MINT, NO_VALUE), _call(TOKEN, MINT)));
        assertFalse(harness.covers(_rule(ANY, TOKEN, bytes4(0), UNLIMITED), _call(TOKEN, MINT)));
    }

    function test_unknownScopeCoversNothing() public view {
        assertFalse(harness.covers(_rule(4, TOKEN, MINT, NO_VALUE), _call(TOKEN, MINT)));
    }

    /* ------------------------------ value caps ----------------------------- */

    /// @dev The default a template grant carries: the call is authorized, the
    ///      ETH is not. Without this a `mint` rule would also authorize
    ///      draining the account's balance to the token address.
    function test_zeroMaxValueForbidsValue() public view {
        CapabilityRule memory rule = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT, 0)));
        assertFalse(harness.covers(rule, _call(TOKEN, MINT, 1)));
    }

    function test_valueCapIsInclusive() public view {
        CapabilityRule memory rule = _rule(EXACT, TOKEN, MINT, 1 ether);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT, 1 ether)));
        assertTrue(harness.covers(rule, _call(TOKEN, MINT, 1 ether - 1)));
        assertFalse(harness.covers(rule, _call(TOKEN, MINT, 1 ether + 1)));
    }

    function test_unlimitedMaxValueAdmitsAnything() public view {
        CapabilityRule memory rule = _rule(ANY, address(0), bytes4(0), UNLIMITED);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT, type(uint256).max)));
    }

    /// @dev The ceiling applies to `SCOPE_ANY` too: "may call anything" and
    ///      "may spend the balance" stay separate grants.
    function test_anyScopeStillRespectsValueCap() public view {
        CapabilityRule memory rule = _rule(ANY, address(0), bytes4(0), NO_VALUE);
        assertTrue(harness.covers(rule, _call(TOKEN, MINT, 0)));
        assertFalse(harness.covers(rule, _call(TOKEN, MINT, 1 wei)));
    }

    /// @dev A bare value transfer: no calldata, so no selector, and the only
    ///      thing standing between it and the account's balance is the ceiling.
    function test_bareValueTransferNeedsAValueCap() public view {
        address recipient = address(0xCAFE);
        assertFalse(
            harness.covers(_rule(ANY_SELECTOR, recipient, bytes4(0), NO_VALUE), _call(recipient, bytes4(0), 1 ether))
        );
        assertTrue(
            harness.covers(_rule(ANY_SELECTOR, recipient, bytes4(0), 1 ether), _call(recipient, bytes4(0), 1 ether))
        );
    }

    /// @dev Two rules differing only in ceiling are different leaves, so a
    ///      policy cannot be widened by reusing a tighter rule's proof.
    function test_valueIsPartOfTheLeaf() public view {
        assertTrue(harness.leaf(_rule(EXACT, TOKEN, MINT, 1 ether)) != harness.leaf(_rule(EXACT, TOKEN, MINT, 2 ether)));
    }

    function test_raisingTheCapChangesTheRoot() public view {
        CapabilityRule[] memory tight = new CapabilityRule[](1);
        tight[0] = _rule(EXACT, TOKEN, MINT, 1 ether);

        CapabilityRule[] memory loose = new CapabilityRule[](1);
        loose[0] = _rule(EXACT, TOKEN, MINT, UNLIMITED);

        assertTrue(harness.root(tight) != harness.root(loose));
    }

    /* ------------------------------ admitsAll ------------------------------ */

    function test_zeroRootAdmitsAnythingWithNoGrants() public view {
        CommittedCall[] memory calls = new CommittedCall[](2);
        calls[0] = _call(TOKEN, MINT);
        calls[1] = _call(address(0xDEAD), TRANSFER, 5 ether);

        assertTrue(harness.admitsAll(IFrameOpcodeAdapter(address(mock)), bytes32(0), calls, new CapabilityGrant[](0)));
    }

    function test_treasuryRefusesTransfer() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = PROOF_MINT;

        assertFalse(
            _admits(ROOT_MINT_BURN, _call(TOKEN, TRANSFER), _rule(ANY_TARGET, address(0), MINT, NO_VALUE), proof)
        );
    }

    /// @dev A rule that covers the call but is not in the policy. The forgery
    ///      case: the grant describes exactly what is wanted and the proof is
    ///      the only thing standing in the way.
    function test_ruleOutsidePolicyRefused() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = PROOF_MINT;

        assertFalse(
            _admits(ROOT_MINT_BURN, _call(TOKEN, TRANSFER), _rule(ANY_TARGET, address(0), TRANSFER, NO_VALUE), proof)
        );
    }

    /// @dev The same rule with a raised ceiling is a different leaf, so this is
    ///      the forgery that matters most for value: keep the scope, lift the cap.
    function test_raisedCapRefusedAgainstTheStoredPolicy() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = PROOF_MINT;

        assertFalse(
            _admits(ROOT_MINT_BURN, _call(TOKEN, MINT, 1 ether), _rule(ANY_TARGET, address(0), MINT, UNLIMITED), proof)
        );
    }

    function test_wrongProofRefused() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(0xBAD));

        assertFalse(_admits(ROOT_MINT_BURN, _call(TOKEN, MINT), _rule(ANY_TARGET, address(0), MINT, NO_VALUE), proof));
    }

    function test_grantCountMismatchRefused() public view {
        CommittedCall[] memory calls = new CommittedCall[](2);
        calls[0] = _call(TOKEN, MINT);
        calls[1] = _call(TOKEN, BURN);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = PROOF_MINT;

        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = _grant(_rule(ANY_TARGET, address(0), MINT, NO_VALUE), proof);

        assertFalse(harness.admitsAll(IFrameOpcodeAdapter(address(mock)), ROOT_MINT_BURN, calls, grants));
    }

    /// @dev Every call must be admitted, not merely the first: a batch that
    ///      opens with a permitted mint and closes with a forbidden transfer is
    ///      the shape this layer exists to stop.
    function test_oneRefusedCallRefusesTheBatch() public view {
        CommittedCall[] memory calls = new CommittedCall[](2);
        calls[0] = _call(TOKEN, MINT);
        calls[1] = _call(TOKEN, TRANSFER);

        assertFalse(harness.admitsAll(IFrameOpcodeAdapter(address(mock)), ROOT_MINT_BURN, calls, _mintBurnGrants()));
    }

    function test_treasuryAdmitsMintAndBurnBatch() public view {
        CommittedCall[] memory calls = new CommittedCall[](2);
        calls[0] = _call(TOKEN, MINT);
        calls[1] = _call(address(0xDEAD), BURN);

        assertTrue(harness.admitsAll(IFrameOpcodeAdapter(address(mock)), ROOT_MINT_BURN, calls, _mintBurnGrants()));
    }

    /// @dev The per-frame ceiling is exactly that. Ten frames each at the cap
    ///      move ten times it, and no VERIFY frame can keep the running total
    ///      that would stop them.
    function test_perFrameCapDoesNotBoundTheTransaction() public view {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(EXACT, TOKEN, MINT, 1 ether);
        bytes32 policyRoot = harness.root(rules);

        CommittedCall[] memory calls = new CommittedCall[](3);
        CapabilityGrant[] memory grants = new CapabilityGrant[](3);
        for (uint256 i = 0; i < 3; i++) {
            calls[i] = _call(TOKEN, MINT, 1 ether);
            grants[i] = _grant(rules[0], new bytes32[](0));
        }

        assertTrue(
            harness.admitsAll(IFrameOpcodeAdapter(address(mock)), policyRoot, calls, grants),
            "3 ether moved under a 1 ether per-frame cap"
        );
    }

    /* ------------------------------ computeRoot ---------------------------- */

    function test_emptyPolicyReverts() public {
        vm.expectRevert(CapabilityLib.EmptyPolicy.selector);
        harness.root(new CapabilityRule[](0));
    }

    function test_unsortedRulesRejected() public {
        CapabilityRule[] memory rules = new CapabilityRule[](2);
        // Treasury, with the two rules the wrong way round.
        rules[0] = _rule(ANY_TARGET, address(0), BURN, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);

        vm.expectRevert(CapabilityLib.UnsortedRules.selector);
        harness.root(rules);
    }

    /// @dev Strict ascent, so a duplicated rule is rejected by the same check.
    function test_duplicateRulesRejected() public {
        CapabilityRule[] memory rules = new CapabilityRule[](2);
        rules[0] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);

        vm.expectRevert(CapabilityLib.UnsortedRules.selector);
        harness.root(rules);
    }

    function test_nonCanonicalRuleRejected() public {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(ANY_TARGET, TOKEN, MINT, NO_VALUE);

        vm.expectRevert(abi.encodeWithSelector(CapabilityLib.NonCanonicalRule.selector, uint256(0)));
        harness.root(rules);
    }

    function test_exactRuleWithEmptyHalfRejected() public {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(EXACT, TOKEN, bytes4(0), NO_VALUE);

        vm.expectRevert(abi.encodeWithSelector(CapabilityLib.NonCanonicalRule.selector, uint256(0)));
        harness.root(rules);
    }

    function test_unknownScopeRejected() public {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(9, address(0), bytes4(0), NO_VALUE);

        vm.expectRevert(abi.encodeWithSelector(CapabilityLib.NonCanonicalRule.selector, uint256(0)));
        harness.root(rules);
    }

    /// @dev Distinct scopes never collide, which is the reason scope is its own
    ///      leaf field rather than a sentinel in the target or selector.
    function test_scopesProduceDistinctLeaves() public view {
        bytes32 anyTarget = harness.leaf(_rule(ANY_TARGET, address(0), MINT, NO_VALUE));
        bytes32 exact = harness.leaf(_rule(EXACT, TOKEN, MINT, NO_VALUE));
        bytes32 anySelector = harness.leaf(_rule(ANY_SELECTOR, TOKEN, bytes4(0), NO_VALUE));
        bytes32 anyScope = harness.leaf(_rule(ANY, address(0), bytes4(0), NO_VALUE));

        assertTrue(anyTarget != exact);
        assertTrue(anyTarget != anySelector);
        assertTrue(anyTarget != anyScope);
        assertTrue(exact != anySelector);
        assertTrue(exact != anyScope);
        assertTrue(anySelector != anyScope);
    }

    /* ------------------------------- helpers ------------------------------- */

    function _grant(CapabilityRule memory rule, bytes32[] memory proof) internal pure returns (CapabilityGrant memory) {
        return
            CapabilityGrant({
                rule: rule, proof: proof, constraints: new ArgConstraint[](0), setProofs: new bytes32[][](0)
            });
    }

    function _mintBurnGrants() internal pure returns (CapabilityGrant[] memory grants) {
        bytes32[] memory mintProof = new bytes32[](1);
        mintProof[0] = PROOF_MINT;
        bytes32[] memory burnProof = new bytes32[](1);
        burnProof[0] = PROOF_BURN;

        grants = new CapabilityGrant[](2);
        grants[0] = _grant(_rule(ANY_TARGET, address(0), MINT, NO_VALUE), mintProof);
        grants[1] = _grant(_rule(ANY_TARGET, address(0), BURN, NO_VALUE), burnProof);
    }

    function _admits(bytes32 policyRoot, CommittedCall memory call, CapabilityRule memory rule, bytes32[] memory proof)
        internal
        view
        returns (bool)
    {
        CommittedCall[] memory calls = new CommittedCall[](1);
        calls[0] = call;

        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = _grant(rule, proof);

        return harness.admitsAll(IFrameOpcodeAdapter(address(mock)), policyRoot, calls, grants);
    }
}
