# ERC-8286 Frame Contracts

> ⚠️ **WARNING: This repository is in active development. The smart contracts and SDK are experimental and have not been audited. DO NOT use in production!**

This repository contains the smart contract implementation for **ERC-8286 Frame Accounts**. 

These contracts provide a minimal ERC-8286 account structure that routes `VERIFY` frame validation to installed [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) validator modules, and applies `APPROVE` operations using a highly optimized Yul opcode adapter.

## Architecture

- **`ERC8286FrameAccount`**: The core account contract. It delegates `VERIFY` requests to an installed ERC-7579 validator and processes `APPROVE` requests via the `FrameOpcodeAdapter`.
- **`ERC8286FrameAccountFactory`**: A `CREATE2` factory for deploying deterministic frame accounts.
- **`FrameOpcodeAdapter.yul`**: A singleton Yul adapter that interfaces directly with low-level opcodes to achieve maximum gas efficiency during frame validation and execution.
- **Validators**: Modular validation components implementing `IFrameValidator` (e.g., `MultiSignerFrameValidator`, `PasskeyFrameValidator`).
- **`IntentLib` & `CapabilityLib`**: Libraries for parsing and managing ERC-8286 intents and capabilities.

## Getting Started

### Prerequisites

These contracts use [Foundry](https://book.getfoundry.sh/) as the primary development framework. You will need:
- `forge` and `cast` installed.

### Build

```bash
# Install dependencies (ensure solady, FreshCryptoLib, and openzeppelin are installed)
pnpm install

# Compile the Solidity contracts
forge build
```

> **Note on Yul Compilation:** The `FrameOpcodeAdapter.yul` is compiled directly via `solc` rather than `forge build` because of forge's limitations with standalone Yul files. 

### Testing

```bash
# Run the test suite
forge test
```

## Security & Audits

These contracts deal with core account abstraction, cryptographic validation (e.g., Passkeys via WebAuthn, Multi-signature verification), and low-level opcode interactions. 

Before deploying to mainnet, please ensure they undergo rigorous security audits.

## License

MIT
