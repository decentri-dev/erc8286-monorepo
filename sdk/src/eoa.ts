import { type Address, bytesToHex, concat, type Hex, numberToHex, pad } from "viem";
import { privateKeyToAccount, sign } from "viem/accounts";
import type { EoaAssertion, FrameSigner } from "./types";

/**
 * Re-encodes a secp256k1 signature into the EIP-8141 frame layout: `v ‖ r ‖ s`.
 *
 * Two deviations from what every viem and ethers helper hands back, both
 * silent if you get them wrong. The recovery id leads rather than trails, and
 * it is a bare 0 or 1 rather than Electrum's 27/28 — a node refuses anything
 * above 1. Serializing a signature the usual way therefore costs every
 * transaction signed with it, with no local error to explain why.
 */
export function toFrameSignature(signature: { r: Hex; s: Hex; yParity?: number; v?: bigint }): Hex {
  // viem types these as alternatives even though a signature always carries one;
  // `v` is Electrum-notated, so the parity is what it exceeds 27 by.
  const yParity =
    signature.yParity ?? (signature.v === undefined ? undefined : Number(signature.v) - 27);

  if (yParity !== 0 && yParity !== 1) {
    throw new Error(`Signature has no usable recovery id (yParity ${String(yParity)}).`);
  }

  return concat([
    numberToHex(yParity, { size: 1 }),
    pad(signature.r, { size: 32 }),
    pad(signature.s, { size: 32 }),
  ]);
}

/**
 * A {@link FrameSigner} backed by a raw secp256k1 key, for roster members that
 * are service keys rather than people — the server-side accounts that act
 * unattended under a capability policy.
 *
 * Signs the intent digest directly, with no EIP-191 prefix: the validator's
 * `eoaBindsIntent` compares the entry's reported `msg` against the digest, and
 * a prefixed hash would recover a different signer.
 */
export class EoaFrameSigner implements FrameSigner {
  readonly address: Address;

  constructor(private readonly privateKey: Hex) {
    this.address = privateKeyToAccount(privateKey).address;
  }

  async sign(challenge: Uint8Array): Promise<EoaAssertion> {
    const signature = await sign({
      hash: bytesToHex(challenge),
      privateKey: this.privateKey,
    });

    return {
      signer: { address: this.address },
      signature: toFrameSignature(signature),
    };
  }
}
