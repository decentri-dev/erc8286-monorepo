import { bytesToHex, type Hex, pad, toHex } from "viem";
import type { FrameSigner, PasskeyAssertion, PasskeyKey } from "./types";

/** A passkey the browser is allowed to sign with. */
type CborValue = number | Uint8Array | Map<number, CborValue>;

class CborReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  read(): CborValue {
    const value = this.readItem();
    if (this.offset !== this.bytes.length) {
      throw new Error("Unexpected trailing COSE public key bytes.");
    }
    return value;
  }

  private readItem(): CborValue {
    const initial = this.readByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    const length = this.readLength(additional);

    switch (major) {
      case 0:
        return length;
      case 1:
        return -1 - length;
      case 2:
        return this.readBytes(length);
      case 5: {
        const map = new Map<number, CborValue>();
        for (let index = 0; index < length; index += 1) {
          const key = this.readItem();
          if (typeof key !== "number") {
            throw new Error("Unsupported COSE public key map key.");
          }
          map.set(key, this.readItem());
        }
        return map;
      }
      default:
        throw new Error("Unsupported COSE public key encoding.");
    }
  }

  private readLength(additional: number): number {
    if (additional < 24) {
      return additional;
    }
    if (additional === 24) {
      return this.readByte();
    }
    if (additional === 25) {
      return (this.readByte() << 8) | this.readByte();
    }
    if (additional === 26) {
      return (
        this.readByte() * 0x1000000 +
        ((this.readByte() << 16) | (this.readByte() << 8) | this.readByte())
      );
    }
    throw new Error("Unsupported COSE public key length.");
  }

  private readByte(): number {
    if (this.offset >= this.bytes.length) {
      throw new Error("Unexpected end of COSE public key.");
    }
    const byte = this.bytes[this.offset];
    if (byte === undefined) {
      throw new Error("Unexpected end of COSE public key.");
    }
    this.offset += 1;
    return byte;
  }

  private readBytes(length: number) {
    const end = this.offset + length;
    if (end > this.bytes.length) {
      throw new Error("Unexpected end of COSE public key bytes.");
    }
    const slice = this.bytes.slice(this.offset, end);
    this.offset = end;
    return slice;
  }
}

function decodePasskeyPublicKey(publicKey: string) {
  const normalized = publicKey.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  const bytes = new Uint8Array(Buffer.from(padded, "base64"));
  if (bytes.length === 0) {
    throw new Error("Passkey public key is empty.");
  }
  return bytes;
}

/**
 * Extracts the qx and qy P-256 coordinates from a base64url-encoded WebAuthn/COSE public key.
 */
export function passkeyPublicKeyToCoordinates(publicKey: string): {
  qx: Hex;
  qy: Hex;
} {
  const decoded = new CborReader(decodePasskeyPublicKey(publicKey)).read();
  if (!(decoded instanceof Map)) {
    throw new Error("Passkey public key is not a COSE key.");
  }

  const keyType = decoded.get(1);
  const algorithm = decoded.get(3);
  const curve = decoded.get(-1);
  const x = decoded.get(-2);
  const y = decoded.get(-3);

  if (keyType !== 2 || curve !== 1 || (algorithm !== undefined && algorithm !== -7)) {
    throw new Error("Passkey must use a P-256 ES256 public key.");
  }
  if (!(x instanceof Uint8Array) || x.length !== 32) {
    throw new Error("Passkey P-256 x coordinate is invalid.");
  }
  if (!(y instanceof Uint8Array) || y.length !== 32) {
    throw new Error("Passkey P-256 y coordinate is invalid.");
  }

  return {
    qx: bytesToHex(x).toLowerCase() as Hex,
    qy: bytesToHex(y).toLowerCase() as Hex,
  };
}

export function isP256Passkey(publicKey: string) {
  try {
    passkeyPublicKeyToCoordinates(publicKey);
    return true;
  } catch {
    return false;
  }
}

/** A passkey the browser is allowed to sign with. */
export type PasskeyCredential = PasskeyKey & {
  /** base64url-encoded WebAuthn credential id. */
  credentialId: string;
};

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N / 2n;

function bufferToHex(buffer: ArrayBuffer): Hex {
  return bytesToHex(new Uint8Array(buffer));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer as ArrayBuffer;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Extracts the r and s integers from a DER-encoded ECDSA signature. */
function extractRS(signature: ArrayBuffer): { r: Hex; s: Hex } {
  const sig = new Uint8Array(signature);
  let pos = 2;
  if (sig[pos] !== 0x02) throw new Error("Invalid DER signature format.");

  const rLen = sig[pos + 1];
  if (rLen === undefined) throw new Error("Invalid DER signature format.");
  let r = sig.slice(pos + 2, pos + 2 + rLen);
  if (r.length === 33 && r[0] === 0) r = r.slice(1);

  pos += 2 + rLen;
  if (sig[pos] !== 0x02) throw new Error("Invalid DER signature format.");

  const sLen = sig[pos + 1];
  if (sLen === undefined) throw new Error("Invalid DER signature format.");
  let s = sig.slice(pos + 2, pos + 2 + sLen);
  if (s.length === 33 && s[0] === 0) s = s.slice(1);

  return { r: bufferToHex(toArrayBuffer(r)), s: bufferToHex(toArrayBuffer(s)) };
}

/** Enforces the low-s form the on-chain verifier requires. */
function normalizeS(sHex: Hex): Hex {
  const s = BigInt(sHex);
  return s > P256_HALF_N ? pad(toHex(P256_N - s), { size: 32 }) : pad(sHex, { size: 32 });
}

/**
 * A {@link FrameSigner} backed by a browser WebAuthn passkey. Only touches
 * `navigator.credentials` inside {@link sign}, so importing it server-side is
 * safe; calling `sign` requires a browser.
 */
export class WebAuthnPasskeySigner implements FrameSigner {
  constructor(private readonly allowedSigners: PasskeyCredential[]) {}

  async sign(challenge: Uint8Array): Promise<PasskeyAssertion> {
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: toArrayBuffer(challenge),
        allowCredentials: this.allowedSigners.map((signer) => ({
          type: "public-key",
          id: base64UrlToArrayBuffer(signer.credentialId),
        })),
        userVerification: "required",
      },
    })) as PublicKeyCredential | null;

    if (!credential) throw new Error("Passkey signing was cancelled.");

    const usedCredentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
    const signer = this.allowedSigners.find((s) => s.credentialId === usedCredentialId);
    if (!signer) throw new Error("Unknown passkey used.");

    const response = credential.response as AuthenticatorAssertionResponse;
    const clientDataRaw = new TextDecoder().decode(response.clientDataJSON);
    const challengeIndex = clientDataRaw.indexOf('"challenge":"');
    const typeIndex = clientDataRaw.indexOf('"type":"webauthn.get"');
    if (challengeIndex < 0 || typeIndex < 0) {
      throw new Error("Authenticator response did not contain the expected WebAuthn fields.");
    }

    let clientChallenge: string | undefined;
    try {
      clientChallenge = (JSON.parse(clientDataRaw) as { challenge?: string }).challenge;
    } catch {
      clientChallenge = undefined;
    }
    if (clientChallenge !== bytesToBase64Url(challenge)) {
      throw new Error("Passkey challenge mismatch.");
    }

    const { r, s } = extractRS(response.signature);
    return {
      signer: { qx: signer.qx, qy: signer.qy },
      r,
      s: normalizeS(s),
      authenticatorData: bufferToHex(response.authenticatorData),
      clientDataJSON: bufferToHex(response.clientDataJSON),
      challengeIndex,
      typeIndex,
    };
  }
}
