import { describe, expect, test } from "bun:test";
import { recoverAddress, size, slice, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signerAddress } from "./account";
import { EoaFrameSigner, toFrameSignature } from "./eoa";
import { isEoaAssertion, isEoaKey } from "./types";

const PRIVATE_KEY = `0x${"01".repeat(32)}` as const;
const DIGEST = `0x${"ab".repeat(32)}` as const;

describe("EoaFrameSigner", () => {
  test("a service key's roster leaf is its own address", () => {
    const account = privateKeyToAccount(PRIVATE_KEY);

    // `SignerLib.effectiveSigner` returns the address itself when slot2 is
    // zero, rather than hashing coordinates as it does for a passkey.
    expect(signerAddress({ address: account.address })).toBe(account.address);
    expect(isEoaKey({ address: account.address })).toBe(true);
    expect(isEoaKey({ qx: DIGEST, qy: DIGEST })).toBe(false);
  });

  test("signs the intent digest with no prefix, so the node recovers the signer", async () => {
    const signer = new EoaFrameSigner(PRIVATE_KEY);
    const assertion = await signer.sign(toBytes(DIGEST));

    expect(isEoaAssertion(assertion)).toBe(true);
    expect(size(assertion.signature)).toBe(65);

    // The validator matches the entry's `msg` against the intent digest, so the
    // signature has to recover over the bare digest — an EIP-191 prefix here
    // would recover a different address and fail membership.
    const r = slice(assertion.signature, 1, 33);
    const s = slice(assertion.signature, 33, 65);
    const yParity = Number(slice(assertion.signature, 0, 1));

    const recovered = await recoverAddress({
      hash: DIGEST,
      signature: { r, s, yParity },
    });

    expect(recovered).toBe(signer.address);
  });

  /**
   * The layout the node wants differs from every library helper in two ways at
   * once, and both fail silently — this is the regression that costs the
   * sponsor every transaction it signs.
   */
  test("encodes v first, as a bare recovery id", () => {
    const encoded = toFrameSignature({
      r: `0x${"11".repeat(32)}`,
      s: `0x${"22".repeat(32)}`,
      yParity: 1,
    });

    expect(encoded).toBe(`0x01${"11".repeat(32)}${"22".repeat(32)}`);
  });

  test("derives the recovery id from an Electrum-notated v", () => {
    const fromV = toFrameSignature({
      r: `0x${"11".repeat(32)}`,
      s: `0x${"22".repeat(32)}`,
      v: 28n,
    });

    expect(slice(fromV, 0, 1)).toBe("0x01");
  });

  test("refuses a signature carrying no usable recovery id", () => {
    expect(() =>
      toFrameSignature({ r: `0x${"11".repeat(32)}`, s: `0x${"22".repeat(32)}` }),
    ).toThrow(/recovery id/);
  });
});
