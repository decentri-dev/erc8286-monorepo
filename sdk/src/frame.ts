import type {
  Frame as EngineFrame,
  FrameTransaction as EngineFrameTransaction,
  Signature as EngineSignature,
} from "@open-engine/sdk";
import {
  type Address,
  concat,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  keccak256,
  pad,
  sha256,
  toBytes,
  toHex,
  toRlp,
} from "viem";
import { createSignerRoster, signerAddress } from "./account";
import type { CapabilityGrant } from "./capability";
import type { FrameChain } from "./chain";
import { randomBytes32 } from "./internal";
import {
  type Frame,
  type FrameAssertion,
  type FrameSigner,
  type FrameTransactionBase,
  isEoaAssertion,
  type SignerApproval,
  type SignerKey,
} from "./types";

const INTENT_DOMAIN = keccak256(toBytes("erc8286.v5.intent"));
const LANE_DOMAIN = keccak256(toBytes("erc8286.v5.lane"));

/** No ceiling on what the transaction may charge the account. */
export const UNCAPPED_COST = (1n << 256n) - 1n;

function byteLength(hex: Hex): bigint {
  return BigInt((hex.length - 2) / 2);
}

/**
 * Computes the intent digest and its EIP-8250 lane key from the committed
 * frames. Frames in VERIFY/POST_TX mode are excluded from the commitment.
 *
 * `maxCost` is a ceiling in wei on what the transaction may charge the account,
 * committed so a relayer cannot re-price a signed intent and drain it. Zero means
 * the account pays nothing and the transaction needs a sponsor; see
 * {@link UNCAPPED_COST} for the deliberate opt-out. Rates stay uncommitted, so
 * re-pricing under the ceiling still works.
 */
export function buildIntentDigest(txBase: FrameTransactionBase, salt: Hex, maxCost: bigint) {
  const parts: Hex[] = [];
  let committedCount = 0n;

  for (const frame of txBase.frames) {
    if (frame.mode === 1 || frame.mode === 3) continue;

    const dataLen = byteLength(frame.data);
    parts.push(pad(frame.target, { size: 32 }));
    parts.push(pad(toHex(frame.gasLimit), { size: 32 }));
    parts.push(pad(toHex(frame.mode), { size: 32 }));
    parts.push(pad(toHex(frame.flags), { size: 32 }));
    parts.push(pad(toHex(frame.value), { size: 32 }));
    parts.push(pad(toHex(dataLen), { size: 32 }));
    if (dataLen > 0n) parts.push(keccak256(frame.data));
    committedCount++;
  }

  const preimage = concat([
    INTENT_DOMAIN,
    pad(toHex(txBase.chainId), { size: 32 }),
    pad(txBase.sender, { size: 32 }),
    salt,
    pad(toHex(maxCost), { size: 32 }),
    pad(toHex(committedCount), { size: 32 }),
    concat(parts),
  ]);
  const intentDigest = keccak256(preimage);
  const laneKey = keccak256(concat([LANE_DOMAIN, intentDigest]));

  return { intentDigest, laneKey };
}

const VERIFY_ABI = [
  {
    type: "function",
    name: "verify",
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "approvalMode", type: "uint8" }],
    stateMutability: "nonpayable",
  },
] as const;

const APPROVALS_ABI = {
  type: "tuple[]",
  components: [
    { type: "uint256", name: "sigIndex" },
    { type: "bytes32[]", name: "merkleProof" },
    {
      type: "tuple",
      name: "assertion",
      components: [
        { type: "uint256", name: "challengeIndex" },
        { type: "uint256", name: "typeIndex" },
        { type: "bytes", name: "authenticatorData" },
        { type: "bytes", name: "clientDataJSON" },
      ],
    },
  ],
} as const;

const GRANTS_ABI = {
  type: "tuple[]",
  components: [
    {
      type: "tuple",
      name: "rule",
      components: [
        { type: "uint8", name: "scope" },
        { type: "address", name: "target" },
        { type: "bytes4", name: "selector" },
        { type: "uint256", name: "maxValue" },
        { type: "bytes32", name: "argsHash" },
      ],
    },
    { type: "bytes32[]", name: "proof" },
    {
      type: "tuple[]",
      name: "constraints",
      components: [
        { type: "uint8", name: "argIndex" },
        { type: "uint8", name: "op" },
        { type: "uint256", name: "operand" },
      ],
    },
    { type: "bytes32[][]", name: "setProofs" },
  ],
} as const;

/**
 * Encodes the VERIFY-frame payload: the validator address followed by the
 * `verify(bytes)` call carrying the signer approvals and capability grants.
 *
 * Approvals must be sorted strictly ascending by effective signer address.
 * Grants are positional — one per committed frame, in frame order — and an
 * unrestricted account takes an empty list. The payload rides in a VERIFY frame,
 * which is not committed to the intent digest, so attaching grants invalidates no
 * signature and a proposal signed before a policy landed still broadcasts.
 */
export function encodeVerifyPayload(input: {
  validator: Address;
  salt: Hex;
  maxCost: bigint;
  approvals: SignerApproval[];
  grants?: CapabilityGrant[];
}): Hex {
  const body = encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }, APPROVALS_ABI, GRANTS_ABI],
    [
      input.salt,
      input.maxCost,
      input.approvals.map((approval) => ({
        sigIndex: approval.sigIndex,
        merkleProof: approval.merkleProof,
        // The struct is positional, so an EOA's ignored assertion still has to
        // occupy its slot — zeroed rather than absent.
        assertion: {
          challengeIndex: BigInt(approval.assertion?.challengeIndex ?? 0),
          typeIndex: BigInt(approval.assertion?.typeIndex ?? 0),
          authenticatorData: approval.assertion?.authenticatorData ?? "0x",
          clientDataJSON: approval.assertion?.clientDataJSON ?? "0x",
        },
      })),
      (input.grants ?? []).map((grant) => ({
        rule: grant.rule,
        proof: grant.proof,
        constraints: grant.constraints,
        setProofs: grant.setProofs,
      })),
    ],
  );

  return encodeFunctionData({ abi: VERIFY_ABI, args: [concat([input.validator, body])] });
}

function rlpFrame(frame: Frame) {
  return [
    frame.mode === 0 ? "0x" : toHex(frame.mode),
    frame.flags === 0 ? "0x" : toHex(frame.flags),
    frame.target,
    frame.gasLimit === 0n ? "0x" : toHex(frame.gasLimit),
    frame.value === 0n ? "0x" : toHex(frame.value),
    frame.data === "0x" ? "0x" : frame.data,
  ];
}

/** The engine's name for a frame mode, by the mode number this SDK uses. */
const ENGINE_FRAME_MODE: Record<number, string> = {
  0: "Default",
  1: "Verify",
  2: "Sender",
};

function engineFrame(frame: Frame): EngineFrame {
  const mode = ENGINE_FRAME_MODE[frame.mode];
  // Mode 3 (POST_TX) has no engine equivalent. Failing here is the point: a
  // silent fallback would submit a frame the engine reads as a different mode.
  if (mode === undefined) throw new Error(`Frame mode ${frame.mode} has no engine equivalent.`);

  return {
    mode,
    flags: frame.flags,
    target: frame.target,
    gas_limit: Number(frame.gasLimit),
    value: frame.value.toString(),
    data: frame.data,
  };
}

/**
 * Rewrites one RLP signature entry into the engine's object form.
 *
 * Deliberately derived from the same `[scheme, signer, msg, signature]` tuple
 * that goes into the envelope rather than rebuilt from the assertion, so the
 * bytes the engine re-encodes cannot drift from the bytes this SDK signed over.
 */
function engineSignature([scheme, signer, msg, signature]: SignatureEntry): EngineSignature {
  return {
    // RLP encodes zero as the empty string, so scheme 0 (ARBITRARY) arrives as
    // "0x" — which `Number` reads as NaN, and JSON as null. Nothing here emits
    // ARBITRARY, but the envelope form permits it, so the mapping is kept total.
    scheme: scheme === "0x" ? 0 : Number(scheme),
    signer,
    msg,
    signature,
  };
}

export type SignedFrameTransaction = {
  /** RLP-encoded type-`0x06` transaction, ready for `eth_sendRawTransaction`. */
  rawTransaction: Hex;
  /**
   * The same transaction as a structured body, for relaying through an engine
   * instead of broadcasting the bytes directly. Built from the identical frames
   * and signatures as `rawTransaction`, so the two always describe one
   * transaction.
   */
  payload: EngineFrameTransaction;
  frameTxHash: Hex;
  intentDigest: Hex;
  laneKey: Hex;
  salt: Hex;
};

/**
 * EIP-8141 signature schemes, numbered as the node numbers them: `0` ARBITRARY,
 * `1` SECP256K1, `2` P-256. An earlier spec revision had SECP256K1 at `0` and
 * P-256 at `1`; a node on the current revision reads a P-256 blob tagged `1` as
 * a 65-byte secp256k1 signature and rejects it. `IntentLib.SCHEME_*` in the v5
 * validator reads the same numbers back out of SIGPARAM and must agree.
 */
const SCHEME_SECP256K1 = "0x01" as const;
const SCHEME_P256 = "0x02" as const;

/** One RLP signature-list entry: `[scheme, signer, msg, signature]`. */
type SignatureEntry = [scheme: Hex, signer: Address, msg: Hex, signature: Hex];

/** One signature-list entry `[scheme, signer, msg, sig]`, per roster variant. */
function signatureEntry(
  assertion: FrameAssertion,
  address: Address,
  intentDigest: Hex,
): SignatureEntry {
  // An EOA signs the intent digest itself, which is what `eoaBindsIntent` then
  // matches the entry's `msg` against.
  if (isEoaAssertion(assertion)) {
    return [SCHEME_SECP256K1, address, intentDigest, assertion.signature];
  }

  // P-256 message = sha256(authenticatorData ‖ sha256(clientDataJSON)).
  const msgHash = sha256(concat([assertion.authenticatorData, sha256(assertion.clientDataJSON)]));
  const blob = concat([
    pad(assertion.r, { size: 32 }),
    pad(assertion.s, { size: 32 }),
    assertion.signer.qx,
    assertion.signer.qy,
  ]);
  return [SCHEME_P256, address, msgHash, blob];
}

/**
 * Assembles the `0x06` envelope from already-collected assertions. Pure and
 * synchronous — no signing happens here — so it works for both the live path
 * and asynchronous multi-party collection, where each signer's assertion was
 * gathered and persisted separately against a fixed `salt`.
 *
 * The `salt` and `txBase` MUST be byte-identical to the ones the assertions
 * were signed over, or the resulting transaction will fail on-chain. The first
 * frame must be the VERIFY frame (mode 1) — its data is replaced with the
 * signature payload. Signatures/approvals are ordered by effective signer
 * address to satisfy the validator's threshold.
 *
 * @param roster The account's full signer set, needed to build membership
 *   proofs. Defaults to exactly the signing keys, which is correct for a
 *   single-member roster (empty proof).
 */
export function assembleFrameTransaction(input: {
  chain: FrameChain;
  txBase: FrameTransactionBase;
  salt: Hex;
  /** Ceiling in wei on what this may charge the account; see {@link buildIntentDigest}. */
  maxCost: bigint;
  assertions: FrameAssertion[];
  /** One per committed frame, in frame order. Empty for an unrestricted account. */
  grants?: CapabilityGrant[];
  roster?: SignerKey[];
  /**
   * Sponsor paying gas, when the frames carry a `pay` frame targeting it. Adds
   * an empty SECP256K1 entry for the relayer to fill; appended last so the
   * passkey entries keep the indices the VERIFY payload already references.
   */
  sponsor?: Address;
  /** The declared payer intent. Required by the engine to match the resolved payer. */
  payer: "self" | "sponsor" | "external";
}): SignedFrameTransaction {
  if (input.assertions.length === 0) throw new Error("At least one assertion is required.");

  const { intentDigest, laneKey } = buildIntentDigest(input.txBase, input.salt, input.maxCost);

  // Sort strictly ascending by effective signer address (the on-chain order and
  // dedupe rule), then reject duplicates.
  const approvers = input.assertions
    .map((assertion) => ({ assertion, address: signerAddress(assertion.signer) }))
    .sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));

  const seen = new Set<string>();
  for (const { address } of approvers) {
    if (seen.has(address)) throw new Error(`Duplicate signer ${address} in approvals.`);
    seen.add(address);
  }

  const roster = createSignerRoster(input.roster ?? input.assertions.map((a) => a.signer));
  const signatures = approvers.map(({ assertion, address }) =>
    signatureEntry(assertion, address, intentDigest),
  );

  // Empty `msg` means the sponsor signs the canonical transaction hash, and that
  // hash elides the signature bytes of exactly such entries — so the placeholder
  // and the filled entry hash identically and the relayer changes nothing.
  if (input.sponsor) signatures.push([SCHEME_SECP256K1, input.sponsor, "0x", "0x"]);
  const approvals: SignerApproval[] = approvers.map(({ assertion }, index) => ({
    sigIndex: BigInt(index),
    merkleProof: roster.proofFor(assertion.signer),
    assertion: isEoaAssertion(assertion) ? undefined : assertion,
  }));

  const verifyData = encodeVerifyPayload({
    validator: input.chain.validator,
    salt: input.salt,
    maxCost: input.maxCost,
    approvals,
    grants: input.grants,
  });
  const frames = input.txBase.frames.map((frame, index) =>
    index === 0 ? { ...frame, data: verifyData } : frame,
  );

  // The EIP-8250 frame transaction envelope expects exactly 11 fields.
  const payload = toRlp([
    toHex(input.txBase.chainId),
    [laneKey],
    input.txBase.nonce === 0n ? "0x" : toHex(input.txBase.nonce),
    input.txBase.sender,
    frames.map(rlpFrame),
    signatures,
    toHex(input.txBase.maxPriorityFeePerGas),
    toHex(input.txBase.maxFeePerGas),
    input.txBase.maxFeePerBlobGas === 0n ? "0x" : toHex(input.txBase.maxFeePerBlobGas),
    input.txBase.blobVersionedHashes,
    [],
  ]);
  const rawTransaction = concat(["0x06", payload]);

  return {
    rawTransaction,
    payload: {
      chain_id: Number(input.txBase.chainId),
      nonce_keys: [laneKey],
      nonce_seq: Number(input.txBase.nonce),
      sender: input.txBase.sender,
      payer: input.payer,
      max_priority_fee_per_gas: Number(input.txBase.maxPriorityFeePerGas),
      max_fee_per_gas: Number(input.txBase.maxFeePerGas),
      max_fee_per_blob_gas: toHex(input.txBase.maxFeePerBlobGas),
      blob_versioned_hashes: input.txBase.blobVersionedHashes,
      frames: frames.map(engineFrame),
      signatures: signatures.map(engineSignature),
    },
    frameTxHash: keccak256(rawTransaction),
    intentDigest,
    laneKey,
    salt: input.salt,
  };
}

/**
 * Signs a frame transaction with live signers and assembles the `0x06`
 * envelope. Each signer approves the same intent digest. For asynchronous
 * collection (sign now, submit later) gather {@link FrameAssertion}s yourself
 * and call {@link assembleFrameTransaction}.
 *
 * @param roster The account's full signer set; defaults to the signing keys.
 */
export async function encodeFrameTransaction(input: {
  chain: FrameChain;
  txBase: FrameTransactionBase;
  signers: FrameSigner[];
  maxCost: bigint;
  grants?: CapabilityGrant[];
  roster?: SignerKey[];
  salt?: Hex;
  payer: "self" | "sponsor" | "external";
}): Promise<SignedFrameTransaction> {
  if (input.signers.length === 0) throw new Error("At least one signer is required.");

  const salt = input.salt ?? randomBytes32();
  const { intentDigest } = buildIntentDigest(input.txBase, salt, input.maxCost);
  const challenge = toBytes(intentDigest);

  // WebAuthn prompts can't overlap, so collect assertions sequentially.
  const assertions: FrameAssertion[] = [];
  for (const signer of input.signers) {
    assertions.push(await signer.sign(challenge));
  }

  return assembleFrameTransaction({
    chain: input.chain,
    txBase: input.txBase,
    salt,
    maxCost: input.maxCost,
    assertions,
    grants: input.grants,
    roster: input.roster,
    payer: input.payer,
  });
}
