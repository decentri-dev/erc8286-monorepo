# Contributing

Welcome, and thank you for your interest in contributing to the ERC-8286 monorepo! 

This repository contains both the smart contracts and the SDK for ERC-8286. 

## Monorepo Setup

This project uses [pnpm](https://pnpm.io/) for managing workspaces. To get started:

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Build all packages:
   ```bash
   pnpm build
   ```

3. Run tests:
   ```bash
   pnpm test
   ```

## Package Structure

- `contracts/`: Contains the Solidity smart contracts (uses Foundry).
- `sdk/`: Contains the TypeScript SDK (uses TypeScript and viem).

## Pull Requests

1. Fork the repository and create your branch from `main`.
2. Make sure you've run the linter and tests before submitting.
3. Ensure your commits are descriptive.
4. Issue a Pull Request with a clear description of the changes.

## License

By contributing to this project, you agree that your contributions will be licensed under its MIT license.
