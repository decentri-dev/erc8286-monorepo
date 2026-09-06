import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import {
  type Address,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  type Hex,
  keccak256,
  zeroAddress,
} from "viem";

/** How broadly one rule applies. Mirrors `CapabilityLib`'s `SCOPE_*`. */
export const CapabilityScope = {
  /** Exactly this function on exactly this contract. */
  EXACT: 0,
  /** This function on any contract. */
  ANY_TARGET: 1,
  /** Any function on this contract. */
  ANY_SELECTOR: 2,
  /** Anything at all. */
  ANY: 3,
} as const;

export type CapabilityScope = (typeof CapabilityScope)[keyof typeof CapabilityScope];

/** Comparison applied to one ABI argument. Mirrors `CapabilityLib`'s `ARG_OP_*`. */
export const ArgOp = {
  EQ: 0,
  LTE: 1,
  GTE: 2,
  /** Member of the set the operand roots — see {@link createValueSet}. */
  IN_SET: 3,
} as const;

export type ArgOp = (typeof ArgOp)[keyof typeof ArgOp];

export const ZERO_SELECTOR = "0x00000000" as Hex;
export const ZERO_HASH = `0x${"00".repeat(32)}` as Hex;

/**
 * A bound on one ABI argument.
 *
 * `argIndex` is a zero-based argument position, not a byte offset, and only
 * *static* parameters can be bound: argument n is read from the word at
 * `4 + 32n`, which is the value itself for `address`, `uintN`, `intN`, `bool`,
 * `bytesN` and enums, but an offset into the tail for `bytes`, `string`, arrays
 * and structs. Nothing on chain can tell the difference — the validator has no
 * ABI — so a constraint on a dynamic parameter verifies happily and bounds
 * nothing. Whoever builds rules holds the ABI and must refuse that.
 */
export type ArgConstraint = {
  argIndex: number;
  op: ArgOp;
  operand: bigint;
};

/** One grant, in the shape the validator hashes into a policy leaf. */
export type CapabilityRule = {
  scope: CapabilityScope;
  target: Address;
  selector: Hex;
  /** Most wei one frame under this rule may carry. Zero forbids value. */
  maxValue: bigint;
  /** {@link argsHashOf} of the rule's constraints, or {@link ZERO_HASH}. */
  argsHash: Hex;
};

/** One committed frame's authorization, as `validateFrame` decodes it. */
export type CapabilityGrant = {
  rule: CapabilityRule;
  proof: Hex[];
  constraints: ArgConstraint[];
  /** One proof per `IN_SET` constraint, in the order those appear. */
  setProofs: Hex[][];
};

// Must match `CapabilityLib.leafOf`: an OpenZeppelin StandardMerkleTree over
// exactly these types, in this order.
const RULE_LEAF_TYPES = ["uint8", "address", "bytes4", "uint256", "bytes32"] as const;

// A set leaf is `abi.encode(uint256)`. Addresses left-pad identically, so an
// address set and a uint256 set of the same values produce the same root.
const VALUE_LEAF_TYPES = ["uint256"] as const;

const ARG_CONSTRAINT_TUPLE = {
  type: "tuple[]",
  components: [{ type: "uint8" }, { type: "uint8" }, { type: "uint256" }],
} as const;

/**
 * `keccak256(abi.encode(ArgConstraint[]))`, the commitment a rule's leaf carries.
 * An empty list is {@link ZERO_HASH} — the rule bounds no arguments.
 *
 * A mismatch with the chain's own encoding does not fail loudly — the rule still
 * verifies against the policy root, and only the grant is refused, at execution
 * time. What guards it is a fixture shared with `CapabilityArgsV5.t.sol`, which
 * pins these hashes on both sides, so drift breaks the build rather than an
 * account. Nothing needs to re-check it against `capabilityArgsHashOf` at runtime.
 */
export function argsHashOf(constraints: readonly ArgConstraint[]): Hex {
  if (constraints.length === 0) return ZERO_HASH;

  return keccak256(
    encodeAbiParameters(
      [ARG_CONSTRAINT_TUPLE],
      [constraints.map((c) => [c.argIndex, c.op, c.operand] as const)],
    ),
  );
}

function ruleLeaf(rule: CapabilityRule) {
  return [rule.scope, getAddress(rule.target), rule.selector, rule.maxValue, rule.argsHash];
}

/** The policy leaf for one rule, matching `CapabilityLib.leafOf`. */
export function capabilityLeafOf(rule: CapabilityRule): Hex {
  return StandardMerkleTree.of([ruleLeaf(rule)], [...RULE_LEAF_TYPES]).root as Hex;
}

export class CapabilityEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CapabilityEncodingError";
  }
}

/**
 * Throws unless the wildcarded half of `rule` is zero and its argument bounds sit
 * on a scope that pins the selector — the same form `CapabilityLib.computeRoot`
 * requires. Rejecting here turns a reverting policy write into a local error.
 */
export function assertCanonicalRule(rule: CapabilityRule): void {
  const noTarget = getAddress(rule.target) === zeroAddress;
  const noSelector = rule.selector === ZERO_SELECTOR;

  const ok =
    rule.scope === CapabilityScope.EXACT
      ? !noTarget && !noSelector
      : rule.scope === CapabilityScope.ANY_TARGET
        ? noTarget && !noSelector
        : rule.scope === CapabilityScope.ANY_SELECTOR
          ? !noTarget && noSelector
          : noTarget && noSelector;

  if (!ok) {
    throw new CapabilityEncodingError(
      `Rule with scope ${rule.scope} must leave its wildcarded half zero.`,
    );
  }

  // "Argument 1 of anything" names no parameter, since every function numbers
  // its own. Only EXACT and ANY_TARGET fix which function is described.
  if (
    rule.argsHash !== ZERO_HASH &&
    rule.scope !== CapabilityScope.EXACT &&
    rule.scope !== CapabilityScope.ANY_TARGET
  ) {
    throw new CapabilityEncodingError(
      "Argument bounds need a scope that pins the selector (EXACT or ANY_TARGET).",
    );
  }
}

/** A policy's Merkle tree: the root the validator stores, plus rule proofs. */
export type CapabilityPolicyTree = {
  root: Hex;
  proofFor(rule: CapabilityRule): Hex[];
};

export function createCapabilityPolicy(rules: readonly CapabilityRule[]): CapabilityPolicyTree {
  if (rules.length === 0) {
    throw new CapabilityEncodingError("A capability policy must hold at least one rule.");
  }

  for (const rule of rules) assertCanonicalRule(rule);

  // Refused here as well as at encoding time: OpenZeppelin builds a tree over
  // duplicate leaves happily, so this would otherwise hand back a root and
  // working-looking proofs for a policy the validator can never store.
  leavesInPolicyOrder(rules);

  const tree = StandardMerkleTree.of(rules.map(ruleLeaf), [...RULE_LEAF_TYPES]);

  return {
    root: tree.root as Hex,
    proofFor(rule) {
      try {
        return tree.getProof(ruleLeaf(rule)) as Hex[];
      } catch {
        throw new CapabilityEncodingError("That rule is not part of this capability policy.");
      }
    },
  };
}

/** The root a rule list produces, without keeping the tree. */
export function computeCapabilityRoot(rules: readonly CapabilityRule[]): Hex {
  return createCapabilityPolicy(rules).root;
}

/** A set backing one `IN_SET` bound: the root a rule cites, plus member proofs. */
export type ValueSetTree = {
  root: Hex;
  proofFor(value: bigint | Address): Hex[];
};

/**
 * Builds the tree for an `IN_SET` operand. Addresses and `uint256`s share an
 * encoding, so one function serves both — pass either.
 */
export function createValueSet(values: readonly (bigint | Address)[]): ValueSetTree {
  if (values.length === 0) {
    throw new CapabilityEncodingError("A value set must hold at least one member.");
  }

  const leaf = (value: bigint | Address) => [typeof value === "bigint" ? value : BigInt(value)];
  const tree = StandardMerkleTree.of(values.map(leaf), [...VALUE_LEAF_TYPES]);

  return {
    root: tree.root as Hex,
    proofFor(value) {
      try {
        return tree.getProof(leaf(value)) as Hex[];
      } catch {
        throw new CapabilityEncodingError(`${value} is not a member of this set.`);
      }
    },
  };
}

const RULE_TUPLE = {
  type: "tuple[]",
  name: "rules",
  components: [
    { type: "uint8", name: "scope" },
    { type: "address", name: "target" },
    { type: "bytes4", name: "selector" },
    { type: "uint256", name: "maxValue" },
    { type: "bytes32", name: "argsHash" },
  ],
} as const;

export const VALIDATOR_ABI = [
  {
    type: "function",
    name: "setCapabilityPolicy",
    inputs: [{ type: "address", name: "account" }, RULE_TUPLE],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getConfig",
    inputs: [{ type: "address", name: "account" }],
    outputs: [
      { type: "uint8", name: "threshold" },
      { type: "uint8", name: "rosterSize" },
      { type: "bytes32", name: "signersRoot" },
      { type: "bytes32", name: "capabilityRoot" },
      { type: "address", name: "admin" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "capabilityRootOf",
    inputs: [RULE_TUPLE],
    outputs: [{ type: "bytes32", name: "root" }],
    stateMutability: "pure",
  },
] as const;

/**
 * Calldata for replacing `account`'s policy.
 *
 * Rules are sorted by leaf hash first, and a repeated rule is refused rather
 * than encoded: the validator rebuilds the root from this list and rejects
 * anything not strictly ascending, which is also what makes the published rule
 * list impossible to pad with a duplicate.
 */
export function encodeSetCapabilityPolicy(account: Address, rules: readonly CapabilityRule[]): Hex {
  for (const rule of rules) assertCanonicalRule(rule);

  return encodeFunctionData({
    abi: VALIDATOR_ABI,
    functionName: "setCapabilityPolicy",
    args: [account, sortRulesForPolicy(rules)],
  });
}

/**
 * Rules paired with their leaf, ascending, with a repeated rule refused.
 *
 * `CapabilityLib.computeRoot` requires each leaf to be strictly greater than the
 * last, so two equal rules are calldata that cannot execute. Sorting alone would
 * place them side by side and hand back something that looks encodable — found
 * at broadcast, after a proposal had collected every signature.
 */
function leavesInPolicyOrder(
  rules: readonly CapabilityRule[],
): { rule: CapabilityRule; leaf: bigint }[] {
  const sorted = rules
    .map((rule) => ({ rule, leaf: BigInt(capabilityLeafOf(rule)) }))
    .sort((a, b) => (a.leaf < b.leaf ? -1 : a.leaf > b.leaf ? 1 : 0));

  for (let index = 1; index < sorted.length; index++) {
    if (sorted[index]?.leaf === sorted[index - 1]?.leaf) {
      throw new CapabilityEncodingError(
        "A capability policy cannot hold the same rule twice. The validator rebuilds the root from the published list and rejects one that is not strictly ascending.",
      );
    }
  }

  return sorted;
}

/** The rules a policy holds, ordered as `setCapabilityPolicy` requires. */
export function sortRulesForPolicy(rules: readonly CapabilityRule[]): CapabilityRule[] {
  return leavesInPolicyOrder(rules).map((entry) => entry.rule);
}
