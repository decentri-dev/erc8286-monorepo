// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";
import {IFrameValidator} from "./IFrameValidator.sol";
import {IntentLib, PasskeyAssertion} from "./IntentLib.sol";

/// @title PasskeyFrameValidator
/// @notice ERC-7579 validator module for single-passkey (WebAuthn/P-256)
///         frame validation, using the same light-hash intent and EIP-8250
///         lane scheme as {MultiSignerFrameValidator} so signing tooling is
///         unified across validator types.
///
/// @dev The passkey signs a WebAuthn assertion whose challenge is the
///      base64url-encoded intent digest (see {IntentLib} for the exact
///      digest layout and lane rules). P-256 verification itself is done by
///      the protocol over `tx.signatures`; this module proves the assertion
///      binds the intent and that the signature belongs to the account's
///      registered passkey.
///
///      Grants whatever scope the frame allows (execution and/or payment):
///      with payment granted the account pays its own gas, but only up to the
///      `maxCost` ceiling the signer committed to (see {IntentLib} "Cost cap").
///      Over it, payment is withdrawn and execution stands.
///
///      This module carries no capability policy — a single-passkey account has
///      one person on its roster and no separation of duties for one to enforce.
///      See {MultiSignerFrameValidator}, which the console deploys for
///      organization accounts.
contract PasskeyFrameValidator is IFrameValidator {
    uint8 internal constant APPROVE_NONE = 0x00;
    uint8 internal constant APPROVE_PAYMENT = 0x01;
    uint8 internal constant APPROVE_EXECUTION = 0x02;

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    IFrameOpcodeAdapter public immutable adapter;

    /// @dev Packed into a single storage slot. Only the protocol-reported
    ///      P256 signer (keccak256(qx || qy)[12:]) is ever needed on-chain,
    ///      so the public key itself is not stored.
    struct Passkey {
        address signer;
        bool installed;
    }

    mapping(address account => Passkey passkey) public passkeys;

    error InvalidAdapter();
    error InvalidInstallData();

    constructor(IFrameOpcodeAdapter adapter_) {
        if (address(adapter_) == address(0)) revert InvalidAdapter();
        adapter = adapter_;
    }

    /// @dev `data` is `qx || qy` (64 bytes). Only the derived signer is
    ///      stored: the protocol reports keccak256(qx || qy)[12:] as the
    ///      P256 signer of a `tx.signatures` entry.
    function onInstall(bytes calldata data) external override {
        if (data.length != 64) revert InvalidInstallData();

        passkeys[msg.sender] = Passkey({signer: address(uint160(uint256(keccak256(data)))), installed: true});
    }

    function onUninstall(bytes calldata) external override {
        delete passkeys[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @inheritdoc IFrameValidator
    /// @dev `data` is `abi.encode(bytes32 salt, uint256 maxCost, uint256 sigIndex,
    ///      PasskeyAssertion assertion)`. Returns APPROVE_NONE on any policy
    ///      failure.
    function validateFrame(bytes32, uint256, uint8 allowedScope, bytes calldata data)
        external
        view
        override
        returns (uint8)
    {
        Passkey memory passkey = passkeys[msg.sender];
        if (!passkey.installed) return APPROVE_NONE;

        // Only validate the account's own transaction (see multi-signer note).
        if (adapter.txParam(IntentLib.TX_PARAM_SENDER) != uint256(uint160(msg.sender))) {
            return APPROVE_NONE;
        }

        (bytes32 salt, uint256 maxCost, uint256 sigIndex, PasskeyAssertion memory assertion) =
            abi.decode(data, (bytes32, uint256, uint256, PasskeyAssertion));

        // The committed calls go unused — no capability policy here. The cost
        // cap does not: a single-signer account is exposed to relayer fee
        // inflation exactly as a multisig one is.
        (bool ok, bytes32 intentDigest,) = IntentLib.buildIntentDigest(adapter, msg.sender, salt, maxCost);
        if (!ok) return APPROVE_NONE;

        if (!IntentLib.laneMatches(adapter, intentDigest)) return APPROVE_NONE;

        if (sigIndex >= adapter.txParam(IntentLib.TX_PARAM_SIG_COUNT)) return APPROVE_NONE;
        if (adapter.sigParam(sigIndex, IntentLib.SIG_PARAM_SCHEME) != IntentLib.SCHEME_P256) {
            return APPROVE_NONE;
        }

        // The signature must belong to this account's registered passkey.
        if (adapter.sigParam(sigIndex, IntentLib.SIG_PARAM_SIGNER) != uint256(uint160(passkey.signer))) {
            return APPROVE_NONE;
        }

        if (!IntentLib.passkeyBindsIntent(adapter, sigIndex, assertion, intentDigest)) {
            return APPROVE_NONE;
        }

        // Grant whatever scope the frame allows, minus payment when the bill
        // exceeds the ceiling the signer approved (see {IntentLib} "Cost cap").
        uint8 mode = allowedScope & (APPROVE_EXECUTION | APPROVE_PAYMENT);
        if ((mode & APPROVE_PAYMENT) != 0 && !IntentLib.costWithinCap(adapter, maxCost)) {
            mode &= ~APPROVE_PAYMENT;
        }

        return mode;
    }
}
