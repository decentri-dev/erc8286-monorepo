import { bytesToHex, type Hex } from "viem";

/** 32 bytes of CSPRNG output, as hex. Available in browsers and Node 19+. */
export function randomBytes32(): Hex {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}
