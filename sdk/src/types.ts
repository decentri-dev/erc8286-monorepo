import type { Address, Hex } from "viem";

/** A single frame within an ERC-8286 v4 frame transaction. */
export type Frame = {
  target: Address;
  gasLimit: bigint;
  /**
   * Execution mode. Modes 1 (VERIFY) and 3 (POST_TX) are *not* committed to the
   * intent digest; every other mode is.
   */
  mode: number;
  flags: number;
  value: bigint;
  data: Hex;
};

/** Everything needed to build a frame transaction, minus the signature. */
export type FrameTransactionBase = {
  chainId: bigint;
  nonce: bigint;
  sender: Address;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  maxFeePerBlobGas: bigint;
  blobVersionedHashes: Hex[];
  frames: Frame[];
};

/** P-256 public-key coordinates of a passkey signer. */
export type PasskeyKey = {
  qx: Hex;
  qy: Hex;
};

/** An EOA signer, identified by the address the protocol reports for it. */
export type EoaKey = {
  address: Address;
};

/**
 * One roster member's public identity, in the two variants `Signer.sol` encodes:
 * an EOA carries its address, a passkey its coordinates. Both reduce to one
 * effective signer address, which is all the roster's Merkle leaves hold.
 */
export type SignerKey = PasskeyKey | EoaKey;

export function isEoaKey(signer: SignerKey): signer is EoaKey {
  return "address" in signer;
}

/**
 * A P-256 WebAuthn assertion over the intent digest. A {@link FrameSigner}
 * produces this; the core turns it into an on-chain VERIFY payload.
 */
export type PasskeyAssertion = {
  signer: PasskeyKey;
  /** Low-s normalized P-256 signature components. */
  r: Hex;
  s: Hex;
  authenticatorData: Hex;
  clientDataJSON: Hex;
  challengeIndex: number;
  typeIndex: number;
};

/**
 * An EOA's approval of the intent digest: one secp256k1 signature, and nothing
 * else. The validator's `eoaBindsIntent` reads only the entry's `msg`, so there
 * is no assertion to carry and no client data to shape-check.
 */
export type EoaAssertion = {
  signer: EoaKey;
  /** 65 bytes, `r ‖ s ‖ v` with a bare 0/1 recovery id as EIP-8141 expects. */
  signature: Hex;
};

/** Either roster variant's approval of one intent digest. */
export type FrameAssertion = PasskeyAssertion | EoaAssertion;

export function isEoaAssertion(assertion: FrameAssertion): assertion is EoaAssertion {
  return isEoaKey(assertion.signer);
}

/**
 * Signs the intent digest. Implementations decide *how* the key is held — a
 * browser passkey (see `@erc8286/sdk/webauthn`), a server-held service key
 * (see {@link EoaFrameSigner}), an HSM, or a test vector — while the core owns
 * assembling the transaction.
 */
export interface FrameSigner {
  sign(challenge: Uint8Array): Promise<FrameAssertion>;
}

/**
 * One roster member's approval, referencing its entry in the transaction's
 * signature list. Approvals are emitted sorted strictly ascending by effective
 * signer address — the on-chain dedupe and ordering rule.
 */
export type SignerApproval = {
  /** Index into the transaction's signature list. */
  sigIndex: bigint;
  /** Sorted-pair Merkle proof that the signer is a member of the roster. */
  merkleProof: Hex[];
  /**
   * Omitted for an EOA entry, which the validator ignores — the struct is still
   * encoded, with every field zeroed.
   */
  assertion?: Pick<
    PasskeyAssertion,
    "challengeIndex" | "typeIndex" | "authenticatorData" | "clientDataJSON"
  >;
};
