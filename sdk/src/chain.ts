import { type Address, getAddress } from "viem";

/**
 * A concrete ERC-8286 deployment. The SDK ships no defaults — the protocol has
 * no canonical chain yet, so every consumer wires its own addresses.
 */
export type FrameChain = {
  chainId: number;
  rpcUrl: string;
  /** ERC8286FrameAccountFactory (CREATE2 account factory). */
  factory: Address;
  /** MultiSignerFrameValidator singleton, installed as the initial validator. */
  validator: Address;
};

/** Normalizes and returns a {@link FrameChain}. */
export function defineFrameChain(chain: FrameChain): FrameChain {
  return {
    ...chain,
    factory: getAddress(chain.factory),
    validator: getAddress(chain.validator),
  };
}
