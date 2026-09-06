# @erc8286/sdk

> ⚠️ **WARNING: This repository is in active development. The smart contracts and SDK are experimental and have not been audited. DO NOT use in production!**

Framework-agnostic toolkit for [ERC-8286](https://eips.ethereum.org/) frame
accounts and transactions. Pure functions over [viem](https://viem.sh) — no RPC calls,
no private keys, no framework assumptions. You build transactions; you decide how they
reach the chain.

> ⚠️ **Unstable.** The EIP is not final and no canonical chain exists yet. Pin an exact
> version and expect breaking changes. All protocol logic lives under `src/` tagged to
> the v4 spec.

## Install

```jsonc
// package.json (bun workspace)
"dependencies": { "@erc8286/sdk": "workspace:*" }
```

Requires `viem` as a peer dependency.

## Configure a deployment

The SDK ships no addresses. Wire your own:

```ts
import { defineFrameChain } from "@erc8286/sdk";

export const chain = defineFrameChain({
  chainId: 3151908,
  rpcUrl: "http://127.0.0.1:8545",
  factory: "0x…", // ERC8286FrameAccountFactory
  validator: "0x…", // MultiSignerFrameValidator singleton
});
```

## Create an account

`createAccountTransaction` returns the deployment calldata plus an address-prediction
read. It sends nothing — bring your own wallet.

```ts
import { createAccountTransaction } from "@erc8286/sdk";

const deploy = createAccountTransaction({ chain, signers, threshold: 2 });
const address = await publicClient.readContract(deploy.predict);
const hash = await walletClient.sendTransaction({ to: deploy.to, data: deploy.data });
```

## Sign a frame transaction

`encodeFrameTransaction` builds the intent digest, collects one signature per signer,
and assembles the raw `0x06` envelope. The first frame must be the VERIFY frame (mode 1).

```ts
import { encodeFrameTransaction } from "@erc8286/sdk";
import { WebAuthnPasskeySigner } from "@erc8286/sdk/webauthn";

const { rawTransaction } = await encodeFrameTransaction({
  chain,
  txBase, // { chainId, nonce, sender, fees…, frames }
  signers: [new WebAuthnPasskeySigner(myPasskeys)],
  payer: "self",
});

await publicClient.request({ method: "eth_sendRawTransaction", params: [rawTransaction] });
```

### Relaying through an engine

The same result also carries `payload`: the identical transaction as a structured body,
for handing to a relaying engine instead of broadcasting the bytes yourself. An engine
needs the fields rather than the bytes — it identifies its queue slot from them, re-checks
the frame structure, and re-encodes at broadcast time.

```ts
const { payload } = await encodeFrameTransaction({ chain, txBase, signers, payer: "self" });

await fetch(`${engineUrl}/transaction`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(payload),
});
```

Both come from one assembly pass, so they always describe the same transaction. The engine
re-encodes, so its bytes are the ones broadcast and the final hash comes from the engine,
not from `frameTxHash`.

### Threshold (m-of-n)

Pass one signer per signature and the account's full `roster` (needed to build the
membership proofs). Each signer prompts in turn; the SDK sorts the approvals by effective
signer address and attaches each proof — exactly what the on-chain validator expects.

```ts
const { rawTransaction } = await encodeFrameTransaction({
  chain,
  txBase,
  roster: accountSigners, // all n signer public keys (SignerKey[])
  signers: [
    new WebAuthnPasskeySigner([signerA]),
    new WebAuthnPasskeySigner([signerB]),
  ], // collect ≥ threshold signatures
  payer: "self",
});
```

`roster` is optional and defaults to the signing keys — correct for a single-member
account (empty proof). Duplicate or non-member signers throw.

## Custom signers

Any `FrameSigner` works — the WebAuthn passkey signer lives behind the `/webauthn` entry
so server code never imports browser globals. Implement `sign(challenge) => PasskeyAssertion`
to back the key with an HSM, a test vector, or anything else.

## Exports

| Symbol | Purpose |
| --- | --- |
| `defineFrameChain` | Normalize a deployment config |
| `createSignerRoster`, `computeSignersRoot`, `signerAddress` | Roster root, proofs, effective address |
| `createAccountTransaction`, `encodeValidatorInitData`, `FACTORY_ABI` | Account deployment |
| `buildIntentDigest`, `encodeVerifyPayload`, `encodeFrameTransaction` | Frame transactions (1-of-1 to m-of-n) |
| `FrameSigner`, `WebAuthnPasskeySigner` (`/webauthn`) | Signing |
