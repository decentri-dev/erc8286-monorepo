import { describe, expect, test } from "bun:test";
import type { Address, Hex } from "viem";
import {
  ArgOp,
  argsHashOf,
  assertCanonicalRule,
  CapabilityEncodingError,
  type CapabilityRule,
  CapabilityScope,
  computeCapabilityRoot,
  createCapabilityPolicy,
  createValueSet,
  encodeSetCapabilityPolicy,
  sortRulesForPolicy,
  ZERO_HASH,
  ZERO_SELECTOR,
} from "./capability";

/**
 * Every expected value here is produced by the Solidity in
 * `packages/contracts/test/CapabilityV5.t.sol` and `CapabilityArgsV5.t.sol`.
 *
 * This is the file that has to exist. The console computes the root a validator
 * will be asked to verify against, and a divergence between the two encodings is
 * silent: the rule still verifies, only the grant is refused, at execution time
 * on a proposal that already collected its signatures. Two implementations that
 * merely agree with themselves catch none of that — which is exactly how the
 * three-field leaf drifted from the contract's five-field one unnoticed.
 */

const NO_VALUE = 0n;
const UNLIMITED = (1n << 256n) - 1n;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;
const CREATE2_DEPLOYER = "0xeEd646DC7594ca540CfbA8910adAd07ad96197b6" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000acc01" as Address;

const SELECTOR = {
  mint: "0x40c10f19",
  burn: "0x9dc29fac",
  pause: "0x8456cb59",
  unpause: "0x3f4ba83a",
  forcedTransfer: "0x9fc1d0e7",
  setAddressFrozen: "0xc69c09cf",
  freezePartial: "0x125c4a33",
  unfreezePartial: "0x1fe56f7d",
  addModule: "0x1ed86f19",
  removeModule: "0xa0632461",
  callModuleFunction: "0xefb22d33",
  addClaim: "0xb1a34e0d",
  registerIdentity: "0x454a03e0",
} satisfies Record<string, Hex>;

const anyTarget = (selector: Hex): CapabilityRule => ({
  scope: CapabilityScope.ANY_TARGET,
  target: ZERO_ADDRESS,
  selector,
  maxValue: NO_VALUE,
  argsHash: ZERO_HASH,
});

const TEMPLATES: Record<string, { rules: CapabilityRule[]; root: Hex }> = {
  owner: {
    rules: [
      {
        scope: CapabilityScope.ANY,
        target: ZERO_ADDRESS,
        selector: ZERO_SELECTOR,
        maxValue: UNLIMITED,
        argsHash: ZERO_HASH,
      },
    ],
    root: "0xe129b37c5c00fe721695819caffa82b69b04228fe5d6691135af440dd2c91148",
  },
  // Every entry below is also built and asserted in `CapabilityV5.t.sol`. One
  // that is not pins nothing — it is this file agreeing with itself, which is
  // the failure the header describes.
  mintBurn: {
    rules: [anyTarget(SELECTOR.mint), anyTarget(SELECTOR.burn)],
    root: "0xc3562f14b4f50df52c3e36ddec7d98ff091541e2c575489620fc18796ee321f6",
  },
  treasury: {
    rules: [anyTarget(SELECTOR.mint), anyTarget(SELECTOR.burn), anyTarget(SELECTOR.forcedTransfer)],
    root: "0x0b494202ee5de0633e24d867d633e61d34c490f7933296804d4b8779f8e84833",
  },
  transferAgent: {
    rules: [
      anyTarget(SELECTOR.forcedTransfer),
      anyTarget(SELECTOR.setAddressFrozen),
      anyTarget(SELECTOR.freezePartial),
      anyTarget(SELECTOR.unfreezePartial),
      anyTarget(SELECTOR.pause),
      anyTarget(SELECTOR.unpause),
    ],
    root: "0x7a5f6385c63059df6e262752f2676ddb14bf22d36bd9513ed4f94f700a7c0512",
  },
  compliance: {
    rules: [
      anyTarget(SELECTOR.registerIdentity),
      anyTarget(SELECTOR.addClaim),
      anyTarget(SELECTOR.addModule),
      anyTarget(SELECTOR.removeModule),
      anyTarget(SELECTOR.callModuleFunction),
      {
        scope: CapabilityScope.ANY_SELECTOR,
        target: CREATE2_DEPLOYER,
        selector: ZERO_SELECTOR,
        maxValue: NO_VALUE,
        argsHash: ZERO_HASH,
      },
    ],
    root: "0x7bf2ef32807b0220443f34fc97c9623526f5ae3f83fd806dd6c93e53bbc096a6",
  },
};

describe("policy roots match the validator", () => {
  for (const [name, template] of Object.entries(TEMPLATES)) {
    test(name, () => {
      expect(computeCapabilityRoot(template.rules)).toBe(template.root);
    });
  }

  // Six rules is not a power of two, so the tree has an unbalanced level — the
  // shape most likely to expose a folding-order mistake.
  test("declaration order does not change the root", () => {
    const { rules, root } = TEMPLATES.compliance as { rules: CapabilityRule[]; root: Hex };

    expect(computeCapabilityRoot([...rules].reverse())).toBe(root);
    expect(computeCapabilityRoot(sortRulesForPolicy(rules))).toBe(root);
  });
});

describe("proofs match the validator", () => {
  test("mint and burn, one node each", () => {
    const policy = createCapabilityPolicy(TEMPLATES.mintBurn?.rules ?? []);

    expect(policy.proofFor(anyTarget(SELECTOR.mint))).toEqual([
      "0x9c54cc56e5a42ca880ad701c6a5d06609bc37ff2153a7d320c51979fdce12ad9",
    ]);
    expect(policy.proofFor(anyTarget(SELECTOR.burn))).toEqual([
      "0x49be163131c5273356d7ce256de6b9d6d49f6a48366be220ed2b0359a37d3d13",
    ]);
  });

  test("a rule outside the policy has no proof", () => {
    const policy = createCapabilityPolicy(TEMPLATES.mintBurn?.rules ?? []);

    expect(() => policy.proofFor(anyTarget(SELECTOR.pause))).toThrow();
  });
});

/**
 * `CapabilityLib.computeRoot` requires strictly ascending leaves, so a repeated
 * rule is calldata that reverts. Left to the chain to catch, it is caught after
 * the proposal carrying it has collected every signature.
 */
describe("a repeated rule is refused locally", () => {
  const duplicated = [anyTarget(SELECTOR.mint), anyTarget(SELECTOR.burn), anyTarget(SELECTOR.mint)];

  test("sortRulesForPolicy throws rather than placing the twins side by side", () => {
    expect(() => sortRulesForPolicy(duplicated)).toThrow(CapabilityEncodingError);
  });

  test("encodeSetCapabilityPolicy refuses to build the calldata", () => {
    expect(() => encodeSetCapabilityPolicy(ACCOUNT, duplicated)).toThrow(CapabilityEncodingError);
  });

  // OpenZeppelin builds a tree over duplicate leaves without complaint, so this
  // would otherwise return a root and proofs for a policy that cannot be stored.
  test("createCapabilityPolicy refuses to build the tree", () => {
    expect(() => createCapabilityPolicy(duplicated)).toThrow(CapabilityEncodingError);
  });

  test("the same rules without the repeat still encode", () => {
    expect(() => sortRulesForPolicy(duplicated.slice(0, 2))).not.toThrow();
  });
});

describe("argsHash matches abi.encode(ArgConstraint[])", () => {
  test("single constraint", () => {
    expect(argsHashOf([{ argIndex: 1, op: ArgOp.LTE, operand: 1000n }])).toBe(
      "0x2221d3865dfef41718a6ea7c43f6309fbc45c1f05f51e3a021f536c0db9443d9",
    );
  });

  test("two constraints", () => {
    expect(
      argsHashOf([
        { argIndex: 0, op: ArgOp.EQ, operand: 0xcafen },
        { argIndex: 1, op: ArgOp.LTE, operand: 10n ** 18n },
      ]),
    ).toBe("0x6dd33887155a0c49c614c1ae179ab3e2a55eb71ae57c8109f215a630313e1091");
  });

  test("no constraints is the zero hash, not a hash of nothing", () => {
    expect(argsHashOf([])).toBe(ZERO_HASH);
  });
});

describe("value sets", () => {
  const ALICE = "0x000000000000000000000000000000000000aAaA" as Address;
  const BOB = "0x000000000000000000000000000000000000bBbB" as Address;
  const CAROL = "0x000000000000000000000000000000000000cCcC" as Address;
  const MALLORY = "0x000000000000000000000000000000000000dDdD" as Address;

  test("root matches the validator", () => {
    expect(createValueSet([ALICE, BOB, CAROL]).root).toBe(
      "0x56a99952b4a5d7c660d8957408579d2d77a015f966bb98214793eb8002f923a9",
    );
  });

  // `abi.encode` left-pads both identically, so one tree serves either type.
  test("an address set and the same values as uint256 share a root", () => {
    expect(createValueSet([ALICE, BOB, CAROL]).root).toBe(
      createValueSet([BigInt(ALICE), BigInt(BOB), BigInt(CAROL)]).root,
    );
  });

  test("a non-member has no proof", () => {
    expect(() => createValueSet([ALICE, BOB, CAROL]).proofFor(MALLORY)).toThrow();
  });
});

describe("canonical form", () => {
  test("rejects a wildcarded half that is not zero", () => {
    expect(() =>
      assertCanonicalRule({ ...anyTarget(SELECTOR.mint), target: CREATE2_DEPLOYER }),
    ).toThrow();

    expect(() =>
      assertCanonicalRule({
        scope: CapabilityScope.ANY_SELECTOR,
        target: CREATE2_DEPLOYER,
        selector: SELECTOR.mint,
        maxValue: NO_VALUE,
        argsHash: ZERO_HASH,
      }),
    ).toThrow();
  });

  // "Argument 1 of anything" names no parameter: every function numbers its own.
  test("rejects argument bounds on a scope that does not pin the selector", () => {
    const argsHash = argsHashOf([{ argIndex: 0, op: ArgOp.LTE, operand: 1n }]);

    expect(() =>
      assertCanonicalRule({
        scope: CapabilityScope.ANY_SELECTOR,
        target: CREATE2_DEPLOYER,
        selector: ZERO_SELECTOR,
        maxValue: NO_VALUE,
        argsHash,
      }),
    ).toThrow();

    expect(() => assertCanonicalRule({ ...anyTarget(SELECTOR.mint), argsHash })).not.toThrow();
  });
});
