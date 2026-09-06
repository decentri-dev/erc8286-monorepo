// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {ArgConstraint, CapabilityGrant, CapabilityLib, CapabilityRule} from "../src/erc8286/v1/CapabilityLib.sol";
import {IFrameOpcodeAdapter} from "../src/erc8286/v1/IFrameOpcodeAdapter.sol";
import {IMultiSignerFrameValidator, SignerApproval} from "../src/erc8286/v1/IMultiSignerFrameValidator.sol";
import {CommittedCall, IntentLib, PasskeyAssertion} from "../src/erc8286/v1/IntentLib.sol";
import {MultiSignerFrameValidator} from "../src/erc8286/v1/MultiSignerFrameValidator.sol";

/// @dev Stand-in for the FrameOpcodeAdapter singleton. Unlike the v4 mock this
///      implements `frameDataLoad`, which the capability layer needs to read a
///      frame's selector.
contract MockFrameAdapterV1 is IFrameOpcodeAdapter {
    struct MockFrame {
        uint256 target;
        uint256 gasLimit;
        uint256 mode;
        uint256 flags;
        uint256 value;
        bytes data;
    }

    struct MockSig {
        address signer;
        uint256 scheme;
        uint256 msgValue;
    }

    mapping(uint256 => uint256) public rawTxParams;
    MockFrame[] internal _frames;
    MockSig[] internal _sigs;
    uint256[] internal _nonceKeys;
    uint256 internal _nonceSeq;

    function setTxParam(uint256 param, uint256 value) external {
        rawTxParams[param] = value;
    }

    function addFrame(uint256 target, uint256 gasLimit, uint256 mode, uint256 flags, uint256 value, bytes memory data)
        external
    {
        _frames.push(MockFrame(target, gasLimit, mode, flags, value, data));
    }

    function clearFrames() external {
        delete _frames;
    }

    function addSig(address signer, uint256 scheme, uint256 msgValue) external {
        _sigs.push(MockSig(signer, scheme, msgValue));
    }

    function setLane(uint256 key) external {
        delete _nonceKeys;
        _nonceKeys.push(key);
        _nonceSeq = 0;
    }

    /* --------------------------- adapter surface -------------------------- */

    function txParam(uint256 param) public view returns (uint256) {
        if (param == IntentLib.TX_PARAM_NONCE_SEQ) return _nonceSeq;
        if (param == IntentLib.TX_PARAM_FRAME_COUNT) return _frames.length;
        if (param == IntentLib.TX_PARAM_SIG_COUNT) return _sigs.length;
        return rawTxParams[param];
    }

    function frameParam(uint256 frameIndex, uint256 param) external view returns (uint256) {
        require(frameIndex < _frames.length, "frame oob");
        MockFrame storage frame = _frames[frameIndex];
        if (param == IntentLib.FRAME_PARAM_RESOLVED_TARGET) return frame.target;
        if (param == IntentLib.FRAME_PARAM_GAS_LIMIT) return frame.gasLimit;
        if (param == IntentLib.FRAME_PARAM_MODE) return frame.mode;
        if (param == IntentLib.FRAME_PARAM_FLAGS) return frame.flags;
        if (param == IntentLib.FRAME_PARAM_DATA_LEN) return frame.data.length;
        if (param == IntentLib.FRAME_PARAM_VALUE) return frame.value;
        revert("frame param");
    }

    function frameDataHash(uint256 frameIndex) external view returns (bytes32) {
        require(frameIndex < _frames.length, "frame oob");
        return keccak256(_frames[frameIndex].data);
    }

    function frameData(uint256 frameIndex) external view returns (bytes memory) {
        return _frames[frameIndex].data;
    }

    /// @dev CALLDATALOAD semantics: a 32-byte window, zero-padded past the end.
    ///      Written as a masked word load rather than a byte loop so the double
    ///      models the real adapter's cost — a byte loop would swamp any gas
    ///      measurement taken through this mock.
    function frameDataLoad(uint256 frameIndex, uint256 offset) external view returns (bytes32 value) {
        require(frameIndex < _frames.length, "frame oob");
        bytes memory data = _frames[frameIndex].data;

        assembly ("memory-safe") {
            let len := mload(data)
            if lt(offset, len) {
                value := mload(add(add(data, 0x20), offset))
                let avail := sub(len, offset)
                // Past the end reads whatever follows in memory; mask it off.
                if lt(avail, 32) { value := and(value, not(sub(shl(mul(8, sub(32, avail)), 1), 1))) }
            }
        }
    }

    function frameDataCopy(uint256, uint256, uint256) external pure returns (bytes memory) {
        revert("unsupported");
    }

    function sigParam(uint256 signatureIndex, uint256 param) external view returns (uint256) {
        require(signatureIndex < _sigs.length, "sig oob");
        MockSig storage sig = _sigs[signatureIndex];
        if (param == IntentLib.SIG_PARAM_SIGNER) return uint256(uint160(sig.signer));
        if (param == IntentLib.SIG_PARAM_SCHEME) return sig.scheme;
        if (param == IntentLib.SIG_PARAM_MSG) return sig.msgValue;
        revert("sig param");
    }

    function approve(uint8) external {}

    function approveWithData(bytes calldata, uint8) external {}

    function nonceKey(uint256 index) external view returns (uint256) {
        if (index >= _nonceKeys.length) revert NonceKeyOutOfRange();
        if (index != 0) revert NonceKeyNotExposed();
        return _nonceKeys[0];
    }

    function nonceKeyCount() external view returns (uint256) {
        return _nonceKeys.length;
    }

    function nonceKeysHash() external pure returns (bytes32) {
        revert("unsupported");
    }

    function legacySenderNonce() external view returns (uint256) {
        return rawTxParams[0x0c];
    }

    function recentRootRefCount() external pure returns (uint256) {
        revert("unsupported");
    }

    function recentRootRef(uint256) external pure returns (bytes32, uint256, bytes32) {
        revert("unsupported");
    }

    function recentRootRefLoad(uint256, uint256) external pure returns (uint256) {
        revert("unsupported");
    }

    function txTrace(uint256, uint256) external pure returns (uint256) {
        revert("unsupported");
    }

    function txDiff(uint256, address, uint256) external pure returns (uint256) {
        revert("unsupported");
    }

    function eventDataCopy(uint256, uint256, uint256) external pure returns (bytes memory) {
        revert("unsupported");
    }
}

/// @dev Exposes the digest walk so the extracted calls can be asserted directly.
contract IntentHarnessV1 {
    function build(IFrameOpcodeAdapter adapter, address account, bytes32 salt, uint256 maxCost)
        external
        view
        returns (bool ok, bytes32 digest, CommittedCall[] memory calls)
    {
        return IntentLib.buildIntentDigest(adapter, account, salt, maxCost);
    }

    function lane(bytes32 digest) external pure returns (uint256) {
        return IntentLib.laneKey(digest);
    }

    function leafOf(address signer) external pure returns (bytes32) {
        return IntentLib.leafOf(signer);
    }
}

/// @title MultiSignerFrameValidatorV1Test
/// @notice The capability layer as the validator actually applies it: config
///         storage, who may write a policy, and the full validation path.
contract MultiSignerFrameValidatorV1Test is Test {
    uint8 constant APPROVE_NONE = 0x00;
    uint8 constant APPROVE_PAYMENT = 0x01;
    uint8 constant APPROVE_EXECUTION = 0x02;
    uint8 constant SCOPE_BOTH = 0x03;

    uint256 constant MODE_VERIFY = 1;
    uint256 constant MODE_SENDER = 2;

    uint8 constant ANY_TARGET = 1;
    uint8 constant ANY_SELECTOR = 2;
    uint8 constant ANY = 3;

    uint256 constant NO_VALUE = 0;
    uint256 constant UNLIMITED = type(uint256).max;
    uint256 constant UNCAPPED = type(uint256).max;

    bytes4 constant MINT = 0x40c10f19;
    bytes4 constant BURN = 0x9dc29fac;
    bytes4 constant TRANSFER = 0xa9059cbb;

    bytes32 constant ROOT_TREASURY = 0xc3562f14b4f50df52c3e36ddec7d98ff091541e2c575489620fc18796ee321f6;
    bytes32 constant PROOF_MINT = 0x9c54cc56e5a42ca880ad701c6a5d06609bc37ff2153a7d320c51979fdce12ad9;
    bytes32 constant PROOF_BURN = 0x49be163131c5273356d7ce256de6b9d6d49f6a48366be220ed2b0359a37d3d13;

    MockFrameAdapterV1 mock;
    MultiSignerFrameValidator validator;
    IntentHarnessV1 harness;

    address account = address(0xA11CE);
    address adminAccount = address(0x0deD);
    address token = address(0xBEEF);
    bytes32 salt = bytes32(uint256(0x5A17));

    address signerLow = address(0x1111111111111111111111111111111111111111);
    address signerHigh = address(0x2222222222222222222222222222222222222222);

    bytes32 rosterRoot;
    bytes32[] proofLow;
    bytes32[] proofHigh;

    function setUp() public {
        mock = new MockFrameAdapterV1();
        validator = new MultiSignerFrameValidator(IFrameOpcodeAdapter(address(mock)));
        harness = new IntentHarnessV1();

        bytes32 leafLow = harness.leafOf(signerLow);
        bytes32 leafHigh = harness.leafOf(signerHigh);
        rosterRoot = _pairHash(leafLow, leafHigh);
        proofLow.push(leafHigh);
        proofHigh.push(leafLow);

        vm.prank(account);
        validator.onInstall(abi.encode(uint8(2), uint8(2), rosterRoot, ROOT_TREASURY, adminAccount));

        mock.setTxParam(IntentLib.TX_PARAM_SENDER, uint256(uint160(account)));
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(MINT, account, 1));
    }

    /* ------------------------------- helpers ------------------------------- */

    function _pairHash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(bytes.concat(a, b)) : keccak256(bytes.concat(b, a));
    }

    function _rule(uint8 scope, address target, bytes4 selector, uint256 maxValue)
        internal
        pure
        returns (CapabilityRule memory)
    {
        return CapabilityRule({
            scope: scope, target: target, selector: selector, maxValue: maxValue, argsHash: bytes32(0)
        });
    }

    function _treasuryRules() internal pure returns (CapabilityRule[] memory rules) {
        rules = new CapabilityRule[](2);
        rules[0] = _rule(ANY_TARGET, address(0), MINT, NO_VALUE);
        rules[1] = _rule(ANY_TARGET, address(0), BURN, NO_VALUE);
    }

    function _digestOnLaneWithCap(uint256 maxCost) internal returns (bytes32 digest) {
        bool ok;
        (ok, digest,) = harness.build(IFrameOpcodeAdapter(address(mock)), account, salt, maxCost);
        assertTrue(ok, "digest build failed");
        mock.setLane(harness.lane(digest));
    }

    function _digestOnLane() internal returns (bytes32 digest) {
        bool ok;
        (ok, digest,) = harness.build(IFrameOpcodeAdapter(address(mock)), account, salt, UNCAPPED);
        assertTrue(ok, "digest build failed");
        mock.setLane(harness.lane(digest));
    }

    function _twoEoaApprovals(bytes32 digest) internal returns (SignerApproval[] memory approvals) {
        mock.addSig(signerLow, IntentLib.SCHEME_SECP256K1, uint256(digest));
        mock.addSig(signerHigh, IntentLib.SCHEME_SECP256K1, 0);

        approvals = new SignerApproval[](2);
        approvals[0] = _approval(0, proofLow);
        approvals[1] = _approval(1, proofHigh);
    }

    function _approval(uint256 sigIndex, bytes32[] memory proof) internal pure returns (SignerApproval memory) {
        return SignerApproval({
            sigIndex: sigIndex,
            merkleProof: proof,
            assertion: PasskeyAssertion({
                challengeIndex: 0, typeIndex: 0, authenticatorData: bytes(""), clientDataJSON: bytes("")
            })
        });
    }

    function _grant(CapabilityRule memory rule, bytes32[] memory proof) internal pure returns (CapabilityGrant memory) {
        return
            CapabilityGrant({
                rule: rule, proof: proof, constraints: new ArgConstraint[](0), setProofs: new bytes32[][](0)
            });
    }

    function _grant(uint8 scope, address target, bytes4 selector, uint256 maxValue, bytes32 proofNode)
        internal
        pure
        returns (CapabilityGrant memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = proofNode;
        return _grant(_rule(scope, target, selector, maxValue), proof);
    }

    function _validate(SignerApproval[] memory approvals, CapabilityGrant[] memory grants, uint8 allowedScope)
        internal
        returns (uint8)
    {
        return _validate(approvals, grants, allowedScope, UNCAPPED);
    }

    function _validate(
        SignerApproval[] memory approvals,
        CapabilityGrant[] memory grants,
        uint8 allowedScope,
        uint256 maxCost
    ) internal returns (uint8) {
        vm.prank(account);
        return validator.validateFrame(bytes32(0), 0, allowedScope, abi.encode(salt, maxCost, approvals, grants));
    }

    /// @dev The happy path: quorum met and the one committed call admitted.
    function _mintGrants() internal pure returns (CapabilityGrant[] memory grants) {
        grants = new CapabilityGrant[](1);
        grants[0] = _grant(ANY_TARGET, address(0), MINT, NO_VALUE, PROOF_MINT);
    }

    /* ------------------------------ lifecycle ------------------------------ */

    function test_installStoresCapabilityAndAdmin() public view {
        (uint8 threshold, uint8 size, bytes32 signersRoot, bytes32 capabilityRoot, address admin) =
            validator.getConfig(account);

        assertEq(threshold, 2);
        assertEq(signersRoot, rosterRoot);
        assertEq(capabilityRoot, ROOT_TREASURY);
        assertEq(admin, adminAccount);
    }

    /// @dev The bug this guards is a whole-struct assignment in `updateConfig`:
    ///      a roster rotation would silently clear the policy and hand the
    ///      account unrestricted authority.
    function test_rosterRotationPreservesCapabilityPolicy() public {
        bytes32 newRoster = keccak256("new roster");

        vm.prank(account);
        validator.updateConfig(3, 4, newRoster);

        (uint8 threshold, uint8 size, bytes32 signersRoot, bytes32 capabilityRoot, address admin) =
            validator.getConfig(account);
        assertEq(threshold, 3);
        assertEq(signersRoot, newRoster);
        assertEq(capabilityRoot, ROOT_TREASURY, "policy cleared by a roster rotation");
        assertEq(admin, adminAccount, "admin cleared by a roster rotation");
    }

    function test_installAcceptsUnrestrictedAndSelfAdmin() public {
        address owner = address(0x0Bee);

        vm.prank(owner);
        validator.onInstall(abi.encode(uint8(1), uint8(2), rosterRoot, bytes32(0), address(0)));

        (,,, bytes32 capabilityRoot, address admin) = validator.getConfig(owner);
        assertEq(capabilityRoot, bytes32(0));
        assertEq(admin, address(0));
    }

    /* --------------------------- argument bounds ---------------------------- */

    /// @dev The whole feature, end to end: an Owner writes "Treasury may mint,
    ///      up to 1000", and the identical proposal is admitted at 1000 and
    ///      refused at 1001 with the same quorum, lane and selector.
    function test_argumentBoundAdmitsAndRefusesTheSameCall() public {
        ArgConstraint[] memory constraints = new ArgConstraint[](1);
        constraints[0] = ArgConstraint({argIndex: 1, op: 1, operand: 1000}); // arg 1 <= 1000

        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = CapabilityRule({
            scope: ANY_TARGET,
            target: address(0),
            selector: MINT,
            maxValue: NO_VALUE,
            argsHash: keccak256(abi.encode(constraints))
        });

        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, rules);

        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = CapabilityGrant({
            rule: rules[0],
            proof: new bytes32[](0), // single-rule policy: the leaf is the root
            constraints: constraints,
            setProofs: new bytes32[][](0)
        });

        _mintFrames(1000);
        assertEq(_validate(_twoEoaApprovals(_digestOnLane()), grants, SCOPE_BOTH), SCOPE_BOTH, "at the bound");

        _mintFrames(1001);
        assertEq(_validate(_twoEoaApprovals(_digestOnLane()), grants, SCOPE_BOTH), APPROVE_NONE, "over the bound");
    }

    function _mintFrames(uint256 amount) internal {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(
            uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(MINT, account, amount)
        );
    }

    /* ---------------------------- roster coherence -------------------------- */

    /// @dev The permanent-lockout guard. A threshold above the roster can never
    ///      be met, and because module management is self-called, an account
    ///      whose only validator is unsatisfiable is bricked forever.
    function test_installRejectsThresholdAboveRoster() public {
        vm.prank(address(0xFEED));
        vm.expectRevert(abi.encodeWithSelector(IMultiSignerFrameValidator.ThresholdExceedsRoster.selector, 3, 2));
        validator.onInstall(abi.encode(uint8(3), uint8(2), rosterRoot, bytes32(0), address(0)));
    }

    function test_rotationRejectsThresholdAboveRoster() public {
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IMultiSignerFrameValidator.ThresholdExceedsRoster.selector, 5, 3));
        validator.updateConfig(5, 3, keccak256("new roster"));
    }

    /// @dev Shrinking a roster below the standing threshold is the realistic
    ///      way in: offboard two of three signers, forget to lower the
    ///      threshold, and the account can never transact again.
    function test_shrinkingRosterBelowThresholdRejected() public {
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IMultiSignerFrameValidator.ThresholdExceedsRoster.selector, 2, 1));
        validator.updateConfig(2, 1, keccak256("one signer left"));
    }

    function test_thresholdEqualToRosterAccepted() public {
        vm.prank(account);
        validator.updateConfig(3, 3, keccak256("three of three"));

        (uint8 threshold, uint8 size,,,) = validator.getConfig(account);
        assertEq(threshold, 3);
        assertEq(size, 3);
    }

    /* ------------------------------- cost cap ------------------------------- */

    /// @dev v4's documented production blocker: fees were uncommitted, so a
    ///      relayer could re-price a signed intent and drain the account up to
    ///      the committed gas limits. The signers now approve a ceiling on the
    ///      bill, and over it the payment bit is withdrawn.
    function test_costOverCapWithdrawsPaymentOnly() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 2 ether);

        bytes32 digest = _digestOnLaneWithCap(1 ether);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        // Execution still approved on its own terms; only payment is refused.
        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH, 1 ether), APPROVE_EXECUTION);
    }

    function test_costWithinCapGrantsPayment() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 0.5 ether);

        bytes32 digest = _digestOnLaneWithCap(1 ether);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH, 1 ether), SCOPE_BOTH);
    }

    function test_costCapIsInclusive() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 1 ether);

        bytes32 digest = _digestOnLaneWithCap(1 ether);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH, 1 ether), SCOPE_BOTH);
    }

    /// @dev A zero cap is sponsor-pays: the account never pays, whatever the
    ///      relayer prices the transaction at.
    function test_zeroCapNeverPays() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 1 wei);

        bytes32 digest = _digestOnLaneWithCap(0);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH, 0), APPROVE_EXECUTION);
    }

    /// @dev An execution-only frame is unaffected — the account was never going
    ///      to pay, so gating it on the bill would refuse legitimate re-pricing.
    function test_executionOnlyFrameIgnoresCost() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 100 ether);

        bytes32 digest = _digestOnLaneWithCap(1 ether);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), APPROVE_EXECUTION, 1 ether), APPROVE_EXECUTION);
    }

    /// @dev The cap is committed, not trusted: a relayer that claims a higher
    ///      ceiling than the signers approved builds a different digest, and no
    ///      collected signature matches it.
    function test_relayerCannotRaiseTheCap() public {
        mock.setTxParam(IntentLib.TX_PARAM_MAX_COST, 2 ether);

        bytes32 digest = _digestOnLaneWithCap(1 ether);
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        // Same signatures, payload rewritten to claim a 100 ether ceiling.
        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH, 100 ether), APPROVE_NONE);
    }

    /* --------------------------- policy authorship -------------------------- */

    /// @dev The point of the layer: the subject cannot widen its own policy.
    function test_accountCannotSetItsOwnPolicy() public {
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(IMultiSignerFrameValidator.NotCapabilityAdmin.selector, account, adminAccount)
        );
        validator.setCapabilityPolicy(account, _treasuryRules());
    }

    function test_strangerCannotSetPolicy() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(
            abi.encodeWithSelector(IMultiSignerFrameValidator.NotCapabilityAdmin.selector, account, adminAccount)
        );
        validator.setCapabilityPolicy(account, _treasuryRules());
    }

    function test_adminSetsPolicyAndPublishesRules() public {
        CapabilityRule[] memory rules = _treasuryRules();

        vm.expectEmit(true, false, false, true, address(validator));
        emit IMultiSignerFrameValidator.CapabilityPolicySet(account, ROOT_TREASURY, rules);

        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, rules);

        (,,, bytes32 capabilityRoot,) = validator.getConfig(account);
        assertEq(capabilityRoot, ROOT_TREASURY);
    }

    /// @dev A zero admin means the account administers itself — the Owner case,
    ///      and the only place the recursion can terminate.
    function test_selfAdministeringAccountSetsItsOwnPolicy() public {
        address owner = address(0x0Bee);

        vm.prank(owner);
        validator.onInstall(abi.encode(uint8(1), uint8(2), rosterRoot, bytes32(0), address(0)));

        vm.prank(owner);
        validator.setCapabilityPolicy(owner, _treasuryRules());

        (,,, bytes32 capabilityRoot,) = validator.getConfig(owner);
        assertEq(capabilityRoot, ROOT_TREASURY);
    }

    function test_policyForUninitializedAccountReverts() public {
        vm.prank(adminAccount);
        vm.expectRevert(IMultiSignerFrameValidator.NotInitialized.selector);
        validator.setCapabilityPolicy(address(0xF00D), _treasuryRules());
    }

    /// @dev Clearing a policy is a widening, and deliberately the admin's to make.
    function test_adminCanClearPolicyToUnrestricted() public {
        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, new CapabilityRule[](0));

        (,,, bytes32 capabilityRoot,) = validator.getConfig(account);
        assertEq(capabilityRoot, bytes32(0));
    }

    function test_capabilityRootOfMatchesStoredRoot() public view {
        assertEq(validator.capabilityRootOf(_treasuryRules()), ROOT_TREASURY);
    }

    /* ---------------------------- committed calls --------------------------- */

    function test_digestWalkExtractsTargetAndSelector() public view {
        (bool ok,, CommittedCall[] memory calls) =
            harness.build(IFrameOpcodeAdapter(address(mock)), account, salt, UNCAPPED);

        assertTrue(ok);
        assertEq(calls.length, 1, "VERIFY frame must not be a committed call");
        assertEq(calls[0].target, token);
        assertEq(calls[0].selector, MINT);
    }

    /// @dev A CREATE2 deploy frame carries `salt ‖ initCode`, not an encoded
    ///      function — but a frame shorter than four bytes has no selector at
    ///      all, and must read as zero exactly as the console's
    ///      `committedCalls` records it.
    function test_shortFrameDataYieldsZeroSelector() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 1 ether, hex"AABB");

        (bool ok,, CommittedCall[] memory calls) =
            harness.build(IFrameOpcodeAdapter(address(mock)), account, salt, UNCAPPED);

        assertTrue(ok);
        assertEq(calls.length, 1);
        assertEq(calls[0].selector, bytes4(0));
    }

    function test_emptyFrameDataYieldsZeroSelector() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 1 ether, bytes(""));

        (,, CommittedCall[] memory calls) = harness.build(IFrameOpcodeAdapter(address(mock)), account, salt, UNCAPPED);

        assertEq(calls.length, 1);
        assertEq(calls[0].selector, bytes4(0));
    }

    /* ---------------------------- validation path --------------------------- */

    function test_admittedCallGrantsScope() public {
        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH), SCOPE_BOTH);
    }

    /// @dev The whole reason the layer exists: a full quorum, correctly signed
    ///      and on the right lane, still refused because the account may not
    ///      make this call.
    function test_capabilityRefusesEvenWithFullQuorum() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(TRANSFER, account, 1));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        // The mint rule is genuinely in the policy; it does not cover a transfer.
        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH), APPROVE_NONE);
    }

    function test_forgedRuleRefused() public {
        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        // An unrestricted rule that is not in the treasury policy.
        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = _grant(ANY, address(0), bytes4(0), UNLIMITED, PROOF_MINT);

        assertEq(_validate(approvals, grants, SCOPE_BOTH), APPROVE_NONE);
    }

    function test_missingGrantRefused() public {
        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, new CapabilityGrant[](0), SCOPE_BOTH), APPROVE_NONE);
    }

    /// @dev An unrestricted account needs no grants, which is what keeps the
    ///      layer optional for accounts deployed without a policy.
    function test_unrestrictedAccountNeedsNoGrants() public {
        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, new CapabilityRule[](0));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, new CapabilityGrant[](0), SCOPE_BOTH), SCOPE_BOTH);
    }

    /// @dev Capability is checked after the roster, so an under-signed proposal
    ///      is still refused for the roster's reason and never reaches it.
    function test_belowThresholdStillRefusedWithValidGrant() public {
        bytes32 digest = _digestOnLane();
        mock.addSig(signerLow, IntentLib.SCHEME_SECP256K1, uint256(digest));

        SignerApproval[] memory approvals = new SignerApproval[](1);
        approvals[0] = _approval(0, proofLow);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH), APPROVE_NONE);
    }

    /// @dev Two committed frames, each needing its own grant in frame order.
    function test_batchNeedsAGrantPerFrame() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(MINT, account, 1));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(BURN, account, 1));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        CapabilityGrant[] memory grants = new CapabilityGrant[](2);
        grants[0] = _grant(ANY_TARGET, address(0), MINT, NO_VALUE, PROOF_MINT);
        grants[1] = _grant(ANY_TARGET, address(0), BURN, NO_VALUE, PROOF_BURN);

        assertEq(_validate(approvals, grants, SCOPE_BOTH), SCOPE_BOTH);
    }

    /// @dev Grants pair positionally, so swapping them is a refusal rather than
    ///      a set-membership check that happens to pass.
    function test_grantsOutOfOrderRefused() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(MINT, account, 1));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(BURN, account, 1));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        CapabilityGrant[] memory grants = new CapabilityGrant[](2);
        grants[0] = _grant(ANY_TARGET, address(0), BURN, NO_VALUE, PROOF_BURN);
        grants[1] = _grant(ANY_TARGET, address(0), MINT, NO_VALUE, PROOF_MINT);

        assertEq(_validate(approvals, grants, SCOPE_BOTH), APPROVE_NONE);
    }

    /// @dev The value ceiling, end to end. The Treasury policy grants `mint`
    ///      with no ETH, so the identical call becomes a refusal the moment the
    ///      frame carries value — the quorum, the lane and the selector are all
    ///      unchanged and correct.
    function test_valueOnAnAdmittedCallIsRefused() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 1 wei, abi.encodeWithSelector(MINT, account, 1));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), SCOPE_BOTH), APPROVE_NONE);
    }

    /// @dev And permitted once the policy says so. A one-rule policy allowing a
    ///      capped transfer to a fixed recipient — the shape a real "may pay
    ///      this counterparty" grant takes.
    function test_cappedValueTransferAdmitted() public {
        address recipient = address(0xCAFE);

        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(ANY_SELECTOR, recipient, bytes4(0), 1 ether);

        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, rules);

        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(recipient)), 100_000, MODE_SENDER, 0, 1 ether, bytes(""));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        // A single-rule policy is its own root, so the proof is empty.
        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = _grant(rules[0], new bytes32[](0));

        assertEq(_validate(approvals, grants, SCOPE_BOTH), SCOPE_BOTH);
    }

    /// @dev One wei over the ceiling and the same policy refuses.
    function test_valueOverTheCapRefused() public {
        address recipient = address(0xCAFE);

        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = _rule(ANY_SELECTOR, recipient, bytes4(0), 1 ether);

        vm.prank(adminAccount);
        validator.setCapabilityPolicy(account, rules);

        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x03, 0, bytes(""));
        mock.addFrame(uint256(uint160(recipient)), 100_000, MODE_SENDER, 0, 1 ether + 1, bytes(""));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        CapabilityGrant[] memory grants = new CapabilityGrant[](1);
        grants[0] = _grant(rules[0], new bytes32[](0));

        assertEq(_validate(approvals, grants, SCOPE_BOTH), APPROVE_NONE);
    }

    /// @dev A payment-only frame still gets its capability check; the scope
    ///      mask narrows what is granted, it does not skip the policy.
    function test_paymentOnlyScopeStillChecksCapability() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(account)), 200_000, MODE_VERIFY, 0x01, 0, bytes(""));
        mock.addFrame(uint256(uint160(token)), 100_000, MODE_SENDER, 0, 0, abi.encodeWithSelector(TRANSFER, account, 1));

        bytes32 digest = _digestOnLane();
        SignerApproval[] memory approvals = _twoEoaApprovals(digest);

        assertEq(_validate(approvals, _mintGrants(), APPROVE_PAYMENT), APPROVE_NONE);
    }
}
