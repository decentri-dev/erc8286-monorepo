import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import {
  type Address,
  concat,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  type Hex,
  keccak256,
  zeroAddress,
} from "viem";
import { ZERO_HASH } from "./capability";
import type { FrameChain } from "./chain";
import { randomBytes32 } from "./internal";
import { isEoaKey, type SignerKey } from "./types";

export const FACTORY_ABI = [
  {
    type: "function",
    name: "createAccount",
    inputs: [
      { name: "salt", type: "bytes32" },
      { name: "initialValidator", type: "address" },
      { name: "validatorInitData", type: "bytes" },
    ],
    outputs: [{ name: "account", type: "address" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getAddress",
    inputs: [
      { name: "salt", type: "bytes32" },
      { name: "initialValidator", type: "address" },
      { name: "validatorInitData", type: "bytes" },
    ],
    outputs: [{ name: "account", type: "address" }],
    stateMutability: "view",
  },
] as const;

/**
 * The address EIP-8141 reports for a signer, matching `SignerLib.effectiveSigner`:
 * an EOA's own address, or `keccak256(qx‖qy)[12:]` for a passkey.
 */
export function signerAddress(signer: SignerKey): Address {
  if (isEoaKey(signer)) return getAddress(signer.address);

  const hash = keccak256(concat([signer.qx, signer.qy]));
  return getAddress(`0x${hash.slice(-40)}`);
}

/** The signer roster: its Merkle root plus membership proofs for signing. */
export type SignerRoster = {
  root: Hex;
  /** Sorted-pair proof of `signer`'s membership; throws if not a member. */
  proofFor(signer: SignerKey): Hex[];
};

/**
 * Builds the roster Merkle tree, matching `IntentLib.leafOf` on-chain (an
 * OpenZeppelin `StandardMerkleTree` over `["address"]` leaves). A single-member
 * roster yields empty proofs.
 */
export function createSignerRoster(signers: SignerKey[]): SignerRoster {
  const tree = StandardMerkleTree.of(
    signers.map((signer) => [signerAddress(signer)]),
    ["address"],
  );

  return {
    root: tree.root as Hex,
    proofFor(signer) {
      const address = signerAddress(signer);
      try {
        return tree.getProof([address]) as Hex[];
      } catch {
        throw new Error(`Signer ${address} is not a member of the roster.`);
      }
    },
  };
}

/** Merkle root over the signer set, matching `IntentLib.leafOf` on-chain. */
export function computeSignersRoot(signers: SignerKey[]): Hex {
  return createSignerRoster(signers).root;
}

/**
 * `abi.encode(uint8 threshold, uint8 rosterSize, bytes32 signersRoot,
 * bytes32 capabilityRoot, address admin)` for the validator.
 *
 * A zero `capabilityRoot` installs an unrestricted account; a zero `admin` makes
 * it self-administering. Both land in the CREATE2 initcode hash, so the account's
 * address is a commitment to them and neither can be changed by redeploying.
 */
export function encodeValidatorInitData(input: {
  threshold: number;
  rosterSize: number;
  signersRoot: Hex;
  capabilityRoot: Hex;
  admin: Address;
}): Hex {
  return encodeAbiParameters(
    [
      { type: "uint8" },
      { type: "uint8" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "address" },
    ],
    [input.threshold, input.rosterSize, input.signersRoot, input.capabilityRoot, input.admin],
  );
}

export type CreateAccountTransaction = {
  /** Factory address to send the deployment to. */
  to: Address;
  /** `createAccount` calldata. */
  data: Hex;
  salt: Hex;
  signersRoot: Hex;
  capabilityRoot: Hex;
  validatorInitData: Hex;
  /** viem `readContract` args that predict the counterfactual account address. */
  predict: {
    address: Address;
    abi: typeof FACTORY_ABI;
    functionName: "getAddress";
    args: readonly [Hex, Address, Hex];
  };
};

/**
 * Builds the transaction that deploys a frame account, plus the read that
 * predicts its address. Does not send anything — the caller owns the wallet.
 */
export function createAccountTransaction(input: {
  chain: FrameChain;
  signers: SignerKey[];
  threshold: number;
  /** Policy root the validator enforces; omit for an unrestricted account. */
  capabilityRoot?: Hex;
  /** Account allowed to rewrite the policy; omit to self-administer. */
  admin?: Address;
  salt?: Hex;
}): CreateAccountTransaction {
  const salt = input.salt ?? randomBytes32();
  const signersRoot = computeSignersRoot(input.signers);
  const capabilityRoot = input.capabilityRoot ?? ZERO_HASH;

  const validatorInitData = encodeValidatorInitData({
    threshold: input.threshold,
    rosterSize: input.signers.length,
    signersRoot,
    capabilityRoot,
    admin: input.admin ?? zeroAddress,
  });
  const args = [salt, input.chain.validator, validatorInitData] as const;

  return {
    to: input.chain.factory,
    data: encodeFunctionData({ abi: FACTORY_ABI, functionName: "createAccount", args }),
    salt,
    signersRoot,
    capabilityRoot,
    validatorInitData,
    predict: {
      address: input.chain.factory,
      abi: FACTORY_ABI,
      functionName: "getAddress",
      args,
    },
  };
}
