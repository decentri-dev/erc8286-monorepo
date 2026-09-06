// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {ArgConstraint, CapabilityGrant, CapabilityLib, CapabilityRule} from "../src/erc8286/v1/CapabilityLib.sol";
import {IFrameOpcodeAdapter} from "../src/erc8286/v1/IFrameOpcodeAdapter.sol";
import {CommittedCall} from "../src/erc8286/v1/IntentLib.sol";
import {MockFrameAdapterV1} from "./MultiSignerFrameValidatorV1.t.sol";

contract ArgsHarness {
    function argsSatisfied(IFrameOpcodeAdapter adapter, CapabilityGrant calldata grant, CommittedCall calldata call)
        external
        view
        returns (bool)
    {
        return CapabilityLib.argsSatisfied(adapter, grant, call);
    }

    function root(CapabilityRule[] calldata rules) external pure returns (bytes32) {
        return CapabilityLib.computeRoot(rules);
    }

    function valueLeafOf(uint256 value) external pure returns (bytes32) {
        return CapabilityLib.valueLeafOf(value);
    }
}

/// @title CapabilityArgsV1Test
/// @notice Per-argument bounds: the layer that turns "Treasury may mint" into
///         "Treasury may mint up to X to an approved set".
///
/// @dev The `argsHash` and set-root fixtures below come from
///      OpenZeppelin's merkle-tree package and viem's `encodeAbiParameters` — the
///      encoders the rule builder will use — so a divergence between Solidity's
///      `abi.encode(ArgConstraint[])` and the JS side fails here rather than at
///      validation time on a live account.
contract CapabilityArgsV1Test is Test {
    uint8 constant EXACT = 0;
    uint8 constant ANY_TARGET = 1;
    uint8 constant ANY_SELECTOR = 2;
    uint8 constant ANY = 3;

    uint8 constant OP_EQ = 0;
    uint8 constant OP_LTE = 1;
    uint8 constant OP_GTE = 2;
    uint8 constant OP_IN_SET = 3;

    bytes4 constant MINT = 0x40c10f19; // mint(address,uint256)
    address constant TOKEN = 0x00000000000000000000000000000000000bEEf1;

    // A `mint(address,uint256)` frame: 4 + 32 + 32 bytes.
    uint256 constant MINT_DATA_LEN = 68;

    address constant ALICE = 0x000000000000000000000000000000000000aaaa;
    address constant BOB = 0x000000000000000000000000000000000000BbBB;
    address constant CAROL = 0x000000000000000000000000000000000000CcCc;
    address constant MALLORY = 0x000000000000000000000000000000000000DdDD;

    // StandardMerkleTree over ["address"] — identical to the ["uint256"] root,
    // since abi.encode left-pads both the same way.
    bytes32 constant SET_ROOT = 0x56a99952b4a5d7c660d8957408579d2d77a015f966bb98214793eb8002f923a9;

    ArgsHarness harness;
    MockFrameAdapterV1 mock;

    function setUp() public {
        harness = new ArgsHarness();
        mock = new MockFrameAdapterV1();
    }

    /* ------------------------------- builders ------------------------------ */

    function _mintFrame(address to, uint256 amount) internal {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(TOKEN)), 100_000, 2, 0, 0, abi.encodeWithSelector(MINT, to, amount));
    }

    function _constraint(uint8 argIndex, uint8 op, uint256 operand) internal pure returns (ArgConstraint memory) {
        return ArgConstraint({argIndex: argIndex, op: op, operand: operand});
    }

    function _one(ArgConstraint memory c) internal pure returns (ArgConstraint[] memory list) {
        list = new ArgConstraint[](1);
        list[0] = c;
    }

    function _rule(bytes32 argsHash) internal pure returns (CapabilityRule memory) {
        return CapabilityRule({scope: ANY_TARGET, target: address(0), selector: MINT, maxValue: 0, argsHash: argsHash});
    }

    function _grant(ArgConstraint[] memory constraints, bytes32[][] memory setProofs)
        internal
        pure
        returns (CapabilityGrant memory)
    {
        bytes32 argsHash = constraints.length == 0 ? bytes32(0) : keccak256(abi.encode(constraints));
        return CapabilityGrant({
            rule: _rule(argsHash), proof: new bytes32[](0), constraints: constraints, setProofs: setProofs
        });
    }

    function _grant(ArgConstraint[] memory constraints) internal pure returns (CapabilityGrant memory) {
        return _grant(constraints, new bytes32[][](0));
    }

    function _call() internal pure returns (CommittedCall memory) {
        return CommittedCall({target: TOKEN, selector: MINT, value: 0, frameIndex: 0, dataLen: MINT_DATA_LEN});
    }

    function _callWithLen(uint256 dataLen) internal pure returns (CommittedCall memory) {
        return CommittedCall({target: TOKEN, selector: MINT, value: 0, frameIndex: 0, dataLen: dataLen});
    }

    function _check(CapabilityGrant memory grant, CommittedCall memory call) internal view returns (bool) {
        return harness.argsSatisfied(IFrameOpcodeAdapter(address(mock)), grant, call);
    }

    /* ------------------------------ operators ------------------------------ */

    /// @dev The headline case: "may mint, up to 1000 units".
    function test_lteBoundsAnAmount() public {
        _mintFrame(ALICE, 999);
        assertTrue(_check(_grant(_one(_constraint(1, OP_LTE, 1000))), _call()));

        _mintFrame(ALICE, 1000);
        assertTrue(_check(_grant(_one(_constraint(1, OP_LTE, 1000))), _call()), "cap is inclusive");

        _mintFrame(ALICE, 1001);
        assertFalse(_check(_grant(_one(_constraint(1, OP_LTE, 1000))), _call()));
    }

    function test_gteBoundsAnAmount() public {
        _mintFrame(ALICE, 100);
        assertFalse(_check(_grant(_one(_constraint(1, OP_GTE, 500))), _call()));

        _mintFrame(ALICE, 500);
        assertTrue(_check(_grant(_one(_constraint(1, OP_GTE, 500))), _call()));
    }

    /// @dev An address argument is just its left-padded word, so pinning a
    ///      recipient needs no address-specific machinery.
    function test_eqPinsAnAddressArgument() public {
        _mintFrame(ALICE, 1);
        assertTrue(_check(_grant(_one(_constraint(0, OP_EQ, uint256(uint160(ALICE))))), _call()));

        _mintFrame(MALLORY, 1);
        assertFalse(_check(_grant(_one(_constraint(0, OP_EQ, uint256(uint160(ALICE))))), _call()));
    }

    /// @dev Constraints are ANDed, which is what "up to X, and only to Y" is.
    function test_constraintsAreConjunctive() public {
        ArgConstraint[] memory both = new ArgConstraint[](2);
        both[0] = _constraint(0, OP_EQ, uint256(uint160(ALICE)));
        both[1] = _constraint(1, OP_LTE, 1000);

        _mintFrame(ALICE, 500);
        assertTrue(_check(_grant(both), _call()));

        _mintFrame(ALICE, 5000);
        assertFalse(_check(_grant(both), _call()), "amount out of bounds");

        _mintFrame(MALLORY, 500);
        assertFalse(_check(_grant(both), _call()), "recipient not pinned");
    }

    function test_unknownOperatorRefuses() public {
        _mintFrame(ALICE, 1);
        assertFalse(_check(_grant(_one(_constraint(1, 9, 1000))), _call()));
    }

    /* ---------------------------- set membership ---------------------------- */

    function _setProof(bytes32 a, bytes32 b) internal pure returns (bytes32[][] memory proofs) {
        proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](b == bytes32(0) ? 1 : 2);
        proofs[0][0] = a;
        if (b != bytes32(0)) proofs[0][1] = b;
    }

    /// @dev Fifty permitted recipients would be one rule and one proof, rather
    ///      than fifty leaves the admin republishes whenever the list moves.
    function test_inSetAdmitsAMember() public {
        _mintFrame(ALICE, 1);
        assertTrue(
            _check(
                _grant(
                    _one(_constraint(0, OP_IN_SET, uint256(SET_ROOT))),
                    _setProof(
                        0x1da0990edbafa28b7605c81db96275638c601306c724645d010ceb7e34447fb5,
                        0xb617df5054bb83fff443d553206a1db65232c4d10654a1cb61586ff28191634e
                    )
                ),
                _call()
            )
        );
    }

    /// @dev A shorter proof from the ragged three-leaf tree, so the fixture
    ///      exercises both depths.
    function test_inSetAdmitsACarolAtADifferentDepth() public {
        _mintFrame(CAROL, 1);
        assertTrue(
            _check(
                _grant(
                    _one(_constraint(0, OP_IN_SET, uint256(SET_ROOT))),
                    _setProof(0x2675cd8a8824a90e4374b8774fabc1994a4c4aca3d0231af5ac75d03133d4d26, bytes32(0))
                ),
                _call()
            )
        );
    }

    /// @dev A non-member cannot be proven, whatever proof is supplied.
    function test_inSetRefusesANonMember() public {
        _mintFrame(MALLORY, 1);
        assertFalse(
            _check(
                _grant(
                    _one(_constraint(0, OP_IN_SET, uint256(SET_ROOT))),
                    _setProof(
                        0x1da0990edbafa28b7605c81db96275638c601306c724645d010ceb7e34447fb5,
                        0xb617df5054bb83fff443d553206a1db65232c4d10654a1cb61586ff28191634e
                    )
                ),
                _call()
            )
        );
    }

    /// @dev Bob's proof does not prove Alice, so proofs cannot be swapped
    ///      between members of the same set.
    function test_inSetRefusesAnotherMembersProof() public {
        _mintFrame(ALICE, 1);
        assertFalse(
            _check(
                _grant(
                    _one(_constraint(0, OP_IN_SET, uint256(SET_ROOT))),
                    _setProof(
                        0x50ad43e67b6ea5e1fcfe458a1978be2f05b6dc4a618e06113b96c4ed00e5e80c,
                        0xb617df5054bb83fff443d553206a1db65232c4d10654a1cb61586ff28191634e
                    )
                ),
                _call()
            )
        );
    }

    function test_inSetWithoutAProofRefuses() public {
        _mintFrame(ALICE, 1);
        assertFalse(_check(_grant(_one(_constraint(0, OP_IN_SET, uint256(SET_ROOT)))), _call()));
    }

    /// @dev Leftover proofs mean the payload does not describe what it verified.
    function test_surplusSetProofRefuses() public {
        _mintFrame(ALICE, 1);
        bytes32[][] memory two = new bytes32[][](2);
        two[0] = new bytes32[](2);
        two[0][0] = 0x1da0990edbafa28b7605c81db96275638c601306c724645d010ceb7e34447fb5;
        two[0][1] = 0xb617df5054bb83fff443d553206a1db65232c4d10654a1cb61586ff28191634e;
        two[1] = new bytes32[](0);

        assertFalse(_check(_grant(_one(_constraint(0, OP_IN_SET, uint256(SET_ROOT))), two), _call()));
    }

    /// @dev The set leaf must match the JS encoder for a set the console builds.
    ///      Alice and Bob are siblings in the fixture tree, so each one's leaf
    ///      is the other's first proof element — which is where these come from.
    function test_valueLeafMatchesEncoder() public view {
        assertEq(
            harness.valueLeafOf(uint256(uint160(ALICE))),
            0x50ad43e67b6ea5e1fcfe458a1978be2f05b6dc4a618e06113b96c4ed00e5e80c
        );
        assertEq(
            harness.valueLeafOf(uint256(uint160(BOB))),
            0x1da0990edbafa28b7605c81db96275638c601306c724645d010ceb7e34447fb5
        );
    }

    /* ------------------------------- safety --------------------------------- */

    /// @dev The vulnerability if bounds-checking were skipped: frame data
    ///      zero-pads past its end, so a short frame would read zero for the
    ///      missing argument and satisfy every upper bound.
    function test_shortCalldataCannotSatisfyAnUpperBound() public {
        mock.clearFrames();
        mock.addFrame(uint256(uint160(TOKEN)), 100_000, 2, 0, 0, abi.encodePacked(MINT));

        // Argument 1 is not present at all; a zero read would pass this LTE.
        assertFalse(_check(_grant(_one(_constraint(1, OP_LTE, 1000))), _callWithLen(4)));
    }

    function test_argumentJustPastTheEndRefused() public {
        _mintFrame(ALICE, 1);
        // Argument 2 would need 100 bytes; the frame carries 68.
        assertFalse(_check(_grant(_one(_constraint(2, OP_LTE, type(uint256).max))), _call()));
    }

    /// @dev Constraints are committed by `argsHash`, so a relayer cannot relax
    ///      them: the swapped list hashes to something the rule does not carry.
    function test_relaxedConstraintsRefused() public {
        _mintFrame(ALICE, 5000);

        // A rule committing to "<= 1000", presented with "<= 10000".
        CapabilityGrant memory grant = _grant(_one(_constraint(1, OP_LTE, 10_000)));
        grant.rule.argsHash = keccak256(abi.encode(_one(_constraint(1, OP_LTE, 1000))));

        assertFalse(_check(grant, _call()));
    }

    /// @dev And constraints cannot be dropped entirely.
    function test_droppedConstraintsRefused() public {
        _mintFrame(ALICE, 5000);

        CapabilityGrant memory grant = _grant(new ArgConstraint[](0));
        grant.rule.argsHash = keccak256(abi.encode(_one(_constraint(1, OP_LTE, 1000))));

        assertFalse(_check(grant, _call()));
    }

    /// @dev An unconstrained rule takes no constraints, so a grant cannot
    ///      attach bounds the policy never committed to.
    function test_unconstrainedRuleRejectsConstraints() public {
        _mintFrame(ALICE, 1);

        CapabilityGrant memory grant = _grant(_one(_constraint(1, OP_LTE, 1000)));
        grant.rule.argsHash = bytes32(0);

        assertFalse(_check(grant, _call()));
    }

    function test_unconstrainedRulePassesWithNoConstraints() public {
        _mintFrame(ALICE, type(uint256).max);
        assertTrue(_check(_grant(new ArgConstraint[](0)), _call()));
    }

    /* --------------------------- canonical form ----------------------------- */

    /// @dev "Argument 1 of anything" names no parameter — every function numbers
    ///      its own — so bounds require a pinned selector.
    function test_argsHashRejectedOnAnySelectorScope() public {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = CapabilityRule({
            scope: ANY_SELECTOR, target: TOKEN, selector: bytes4(0), maxValue: 0, argsHash: keccak256("something")
        });

        vm.expectRevert(abi.encodeWithSelector(CapabilityLib.NonCanonicalRule.selector, uint256(0)));
        harness.root(rules);
    }

    function test_argsHashRejectedOnAnyScope() public {
        CapabilityRule[] memory rules = new CapabilityRule[](1);
        rules[0] = CapabilityRule({
            scope: ANY, target: address(0), selector: bytes4(0), maxValue: 0, argsHash: keccak256("something")
        });

        vm.expectRevert(abi.encodeWithSelector(CapabilityLib.NonCanonicalRule.selector, uint256(0)));
        harness.root(rules);
    }

    function test_argsHashAcceptedOnExactAndAnyTarget() public view {
        CapabilityRule[] memory exact = new CapabilityRule[](1);
        exact[0] = CapabilityRule({
            scope: EXACT, target: TOKEN, selector: MINT, maxValue: 0, argsHash: keccak256("something")
        });
        assertTrue(harness.root(exact) != bytes32(0));

        CapabilityRule[] memory anyTarget = new CapabilityRule[](1);
        anyTarget[0] = _rule(keccak256("something"));
        assertTrue(harness.root(anyTarget) != bytes32(0));
    }

    /* ---------------------------- encoder parity ---------------------------- */

    /// @dev `abi.encode(ArgConstraint[])` must match viem's tuple-array encoding,
    ///      or a rule the console builds is unprovable on chain.
    function test_argsHashMatchesEncoder_single() public pure {
        ArgConstraint[] memory list = new ArgConstraint[](1);
        list[0] = ArgConstraint({argIndex: 1, op: 1, operand: 1000});

        assertEq(keccak256(abi.encode(list)), 0x2221d3865dfef41718a6ea7c43f6309fbc45c1f05f51e3a021f536c0db9443d9);
    }

    function test_argsHashMatchesEncoder_pair() public pure {
        ArgConstraint[] memory list = new ArgConstraint[](2);
        list[0] = ArgConstraint({argIndex: 0, op: 0, operand: 0xcafe});
        list[1] = ArgConstraint({argIndex: 1, op: 1, operand: 1e18});

        assertEq(keccak256(abi.encode(list)), 0x6dd33887155a0c49c614c1ae179ab3e2a55eb71ae57c8109f215a630313e1091);
    }
}
