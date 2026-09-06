import type { Address, Hex } from "viem";
import { buildIntentDigest } from "./frame";
import type { Frame, FrameTransactionBase } from "./types";

/**
 * The exact transaction the signers approve, persisted so it can be reassembled
 * and broadcast byte-for-byte after asynchronous collection. Bigints are stored
 * as strings for JSON. Fees are deliberately excluded — they are not committed
 * to the intent digest and are chosen at broadcast time.
 */
export type IntentPayload = {
  chainId: number;
  sender: Address;
  frames: {
    target: Address;
    gasLimit: string;
    mode: number;
    flags: number;
    value: string;
    data: Hex;
  }[];
};

export function freezeIntentPayload(
  sender: Address,
  chainId: number,
  frames: Frame[],
): IntentPayload {
  return {
    chainId,
    sender,
    frames: frames.map((frame) => ({
      target: frame.target,
      gasLimit: frame.gasLimit.toString(),
      mode: frame.mode,
      flags: frame.flags,
      value: frame.value.toString(),
      data: frame.data,
    })),
  };
}

export function framesFromIntentPayload(payload: IntentPayload): Frame[] {
  return payload.frames.map((frame) => ({
    target: frame.target,
    gasLimit: BigInt(frame.gasLimit),
    mode: frame.mode,
    flags: frame.flags,
    value: BigInt(frame.value),
    data: frame.data,
  }));
}

/**
 * Reconstructs a {@link FrameTransactionBase} for digesting or assembly.
 *
 * Like fees, the envelope `nonce` is NOT committed to the intent digest (the
 * EIP-8250 lane key covers replay protection), so it is chosen at broadcast
 * time: pass the account's current protocol nonce. Digest-only callers can
 * omit it.
 */
export function txBaseFromIntentPayload(
  payload: IntentPayload,
  overrides: { maxPriorityFeePerGas: bigint; maxFeePerGas: bigint; nonce?: bigint },
): FrameTransactionBase {
  return {
    chainId: BigInt(payload.chainId),
    nonce: overrides.nonce ?? 0n,
    sender: payload.sender,
    maxPriorityFeePerGas: overrides.maxPriorityFeePerGas,
    maxFeePerGas: overrides.maxFeePerGas,
    maxFeePerBlobGas: 0n,
    blobVersionedHashes: [],
    frames: framesFromIntentPayload(payload),
  };
}

/** Computes the intent digest + lane key for a set of frames and a salt. */
export function digestForFrames(input: {
  chainId: number;
  sender: Address;
  frames: Frame[];
  salt: Hex;
  maxCost: bigint;
}) {
  const txBase = txBaseFromIntentPayload(
    freezeIntentPayload(input.sender, input.chainId, input.frames),
    {
      maxPriorityFeePerGas: 0n,
      maxFeePerGas: 0n,
    },
  );
  return buildIntentDigest(txBase, input.salt, input.maxCost);
}
