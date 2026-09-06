# ERC-8286 Monorepo

> ⚠️ **WARNING: This repository is in active development. The smart contracts and SDK are experimental and have not been audited. DO NOT use in production!**

This repository is a monorepo containing the smart contracts and SDK for **ERC-8286**. 

## Packages

| Package | Description |
|---|---|
| [`@erc8286/contracts`](./contracts/) | Foundry-based smart contracts for ERC-8286. |
| [`@erc8286/sdk`](./sdk/) | Framework-agnostic TypeScript toolkit for interacting with ERC-8286 frame accounts and transactions. |

## Quick Start

This project uses `pnpm` workspaces.

```bash
# Install dependencies across all packages
pnpm install

# Build all packages
pnpm build

# Run tests across all packages
pnpm test
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details on how to set up the repository for development and submit pull requests.

## License

This project is licensed under the [MIT License](./LICENSE).
