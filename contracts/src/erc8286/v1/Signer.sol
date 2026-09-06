// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A single signer: either an EOA (secp256k1) or a passkey (P-256).
/// @dev Two-slot layout, adapted from Splits/Coinbase Smart Wallet.
///      - EOA     -> `slot1` is the 20-byte address, `slot2` is zero.
///      - Passkey -> `slot1` is the public-key x coordinate, `slot2` the y
///        coordinate. A P-256 y coordinate is never zero, which is what
///        distinguishes the two variants.
///      Unlike Splits, this type carries no signature-verification logic: under
///      EIP-8141 the protocol verifies `tx.signatures` before any frame runs, so
///      a `Signer` only needs to describe *who* may sign, not *how* to check a
///      signature. Verification collapses to matching the protocol-reported
///      effective signer address (see `effectiveSigner`).
struct Signer {
    bytes32 slot1;
    bytes32 slot2;
}

using SignerLib for Signer global;

/// @title SignerLib
/// @notice Classification and identity helpers for {Signer}.
library SignerLib {
    bytes32 internal constant ZERO = bytes32(0);

    /// @notice True when `signer` encodes a non-zero EOA address (slot2 empty).
    function isEOAMem(Signer memory signer) internal pure returns (bool) {
        uint256 slot1 = uint256(signer.slot1);
        return signer.slot2 == ZERO && slot1 <= type(uint160).max && slot1 > 0;
    }

    /// @notice True when `signer` encodes a passkey (a P-256 `y` is never zero).
    function isPasskeyMem(Signer memory signer) internal pure returns (bool) {
        return signer.slot2 != ZERO;
    }

    /// @notice True when `signer` is a well-formed EOA or passkey.
    function isValidMem(Signer memory signer) internal pure returns (bool) {
        return isEOAMem(signer) || isPasskeyMem(signer);
    }

    /// @notice The address EIP-8141 reports for this signer via `SIGPARAM(i, 0x00)`.
    /// @dev For an EOA this is the address itself; for a passkey it is
    ///      `keccak256(qx ‖ qy)[12:]`, matching the P256 signer rule in EIP-8141.
    ///      This is the value a multi-signer validator keys its set on.
    function effectiveSigner(Signer memory signer) internal pure returns (address) {
        if (signer.slot2 == ZERO) {
            return address(uint160(uint256(signer.slot1)));
        }
        return address(uint160(uint256(keccak256(abi.encodePacked(signer.slot1, signer.slot2)))));
    }
}
