# Sponsored EIP-7702 Mint Executor

`SponsoredMintExecutor` is a narrow, non-upgradeable executor for sponsored EIP-7702 minting. One sponsor-agnostic deployment is both the batch dispatcher and the code implementation to which eligible EOAs temporarily delegate. The runtime contains no deployment-address or chain-specific immutable, so the same build has identical runtime bytecode at every deployment address and on every compatible chain.

> [!CAUTION]
> **This smart contract has not been independently audited.** It is experimental software and may contain defects or exploitable vulnerabilities. Do not delegate or fund valuable wallets until an independent security audit, deployment review, and chain-specific integration test have been completed.
>
> Use this contract entirely at your own risk. It is provided "as is" without warranties of any kind. To the maximum extent permitted by law, the creator, author, contributors, and copyright holders are not liable for any direct, indirect, incidental, consequential, financial, technical, or other loss, damage, injury, or harm arising from its deployment, use, inability to use, or reliance on it.

## Security boundary

The contract intentionally provides no generic `execute`, `delegatecall`, approval, ERC-20, ownership-transfer, upgrade, initializer, or withdrawal function. The only outbound action exposed through a delegated wallet is one EIP-712-authorized mint operation and its immediate NFT forwarding. Passive receive and signature-validation paths do not make external calls or write persistent wallet storage.

Mint and NFT addresses cannot be the delegated wallet or dispatcher, closing self-callback and permissive-fallback spoofing. Nested mint calldata is limited to 16 KiB, and the dispatcher calls a wallet only when EIP-150 cannot clamp its complete signed gas allowance and a continuation reserve remains.

Every wallet signature binds all security-relevant operation data:

- chain ID and delegated wallet through the EIP-712 domain;
- dispatcher deployment, batch sponsor, batch ID, and operation index;
- wallet, mint target, and the hash of the complete mint calldata;
- mint value, mint gas limit, and wallet execution gas limit;
- expected NFT contract, final recipient, expected token units, and deadline.

The dispatcher permanently consumes `keccak256(abi.encode(sponsor, batchId))` before making external calls. Another sponsor cannot occupy that replay namespace, and the same batch ID may be used independently by different sponsors. A failed wallet cannot be retried by its signed sponsor under the consumed batch ID and does not revert successful wallet calls.

## EIP-7702 protections

- There is no owner, mutable sponsor, initializer, sponsor allowlist, or rotation authority.
- The batch caller pays outer gas only, and every wallet signature binds that exact sponsor.
- Only the deployed dispatcher may call `executeSponsoredMint` through a delegated wallet.
- Each wallet must have code hash `keccak256(0xef0100 || DISPATCHER)` when its operation executes.
- An invalid authorization or wrong delegation is skipped without spending wallet mint value.
- A wallet may appear only once per batch; later duplicates retain their wallet balance.
- The delegated wallet verifies an ERC-2098 compact signature recovered to `address(this)`.
- Low-`s` enforcement prevents ECDSA signature malleability.
- Sponsor, target, calldata, value, gas, deadline, account, chain, batch, and index are signed.
- The full signed wallet gas allowance must be forwardable without EIP-150 clamping.
- Mint calldata is bounded at 16 KiB and executor addresses cannot impersonate mint or NFT contracts.
- Batch replay state exists only on the dispatcher; delegated EOAs receive no persistent storage writes.
- Transient state is explicitly cleared after a successful mint and rolls back on failure.

EIP-7702 delegation persists even when the outer transaction reverts. The CLI must still submit and confirm a separately authorized zero-address revocation, including after a reverted batch.

## Sponsor selection

The contract has no configured sponsor. Before wallet signing, the CLI derives the batch sponsor from the configured sponsor private key and passes that address to `operationDigest`. The same address must call `executeBatch`, but sends zero native value. The dispatcher calls each delegated wallet with zero value; that wallet spends exactly its signed `mintValue` from its own balance and must finish with precisely `balanceBefore - mintValue`.

> [!IMPORTANT]
> Sponsored mode sponsors gas, not NFT price. Each eligible EOA must hold its complete signed mint value before execution. The sponsor pays authorization, dispatch, mint-call, verification, and NFT-forwarding gas through the outer transaction. A failed or skipped operation leaves that wallet's mint balance unchanged.

A replacement sponsor cannot use signatures created for the previous sponsor and must obtain fresh local mint-operation signatures. Previously issued signatures remain valid only for their original sponsor until their deadline, batch consumption, or delegation revocation. Sponsor replacement does not change the executor address, delegation code hash, or an already-active wallet delegation. Replay queries use `isBatchUsed(sponsor, batchId)`, and `WalletExecution` includes the indexed sponsor address.

## Dormant delegation compatibility

Revocation remains mandatory, but a delayed or failed revocation no longer makes the wallet unusable for ordinary activity:

- EIP-7702 explicitly permits a delegated EOA to originate ordinary transactions, so the key can still send ETH and call applications directly.
- Delegated contexts accept plain ETH and unknown calldata with empty returndata. The deployed dispatcher rejects both paths so it cannot become an ordinary deposit target.
- Outside an active sponsored mint, the ERC-721 and ERC-1155 receiver hooks accept tokens and leave them in the wallet. During an active mint, the same hooks enforce and forward the signed mint result.
- ERC-1271 validates 64-byte ERC-2098 and 65-byte canonical ECDSA signatures made by the EOA key, with strict low-`s` and `v` checks.

This is functional compatibility, not identity with a code-free EOA. `EXTCODESIZE` still reports the 23-byte EIP-7702 delegation indicator, applications may reject all code-bearing accounts, and calls whose selector matches an executor function follow that function rather than the fallback. A sender that hard-codes the 21,000-gas EOA transfer limit can also fail because delegated code must execute; senders must estimate gas. Revocation is the only way to restore the account's empty-code behavior everywhere.

## NFT forwarding

During one signed mint, the executor treats a callback as part of that mint only when:

- `msg.sender` is the signed NFT contract;
- `from` is the zero address, proving a safe-mint callback rather than a transfer; and
- the cumulative ERC-721 count or ERC-1155 unit count does not exceed the signed expectation.

Each active-mint NFT is immediately forwarded with the standard safe-transfer function. The transfer must return no data, as required by ERC-721 and ERC-1155. The complete wallet mint reverts unless the forwarded count exactly equals `expectedUnits`. OpenSea's reference ERC-721 SeaDrop token calls `_safeMint`, so its mint path supplies the required receiver callbacks. An NFT contract that performs an unsafe mint or uses non-standard callbacks is deliberately unsupported and fails closed. Outside an active mint, standard safe transfers are accepted without forwarding for EOA-like custody.

## Gas design

- EIP-1153 transient storage carries the callback context for 100 gas per warm `TLOAD` or `TSTORE` operation without persistent wallet storage collisions.
- Duplicate-wallet slots store the sponsor-scoped batch key, avoiding a post-batch cleanup loop while allowing independent sequential sponsor batches in the same transaction.
- ERC-2098 signatures use two ABI words instead of the three words required by `(v,r,s)`.
- Revert data from untrusted calls is never copied in full; only the first four-byte error selector is retained.
- The dispatcher reserves finalization gas plus a bounded amount for every remaining wallet before each call.
- Nested mint calldata is capped at 16 KiB so one signed operation cannot request unbounded copying.
- Custom errors replace revert strings.
- Loop bounds are fixed at 25 wallet operations.
- The optimizer uses the IR pipeline with 10,000 expected runtime executions.
- Compiler metadata hashes are omitted from bytecode for smaller and reproducible compiler output.

The implementation copies nested mint calldata to memory before the external call. This small cost is intentional: direct inline-assembly use of a nested calldata offset is fragile and previously produced an incorrect selector in testing.

## Compatibility

The build targets Solidity `0.8.36` and the Prague EVM. Runtime execution requires:

- EIP-7702 for EOA delegation;
- EIP-1153 for transient callback state;
- EIP-712-compatible signing support; and
- standard ERC-721 or ERC-1155 safe-mint and safe-transfer behavior.

The bytecode must not be deployed on a chain that lacks EIP-1153. Sponsored mode proves both EIP-7702 delegation and EIP-1153 transient storage through read-only state-override calls before deployment or mint signatures.

## Build and test

Run from the repository root:

```powershell
forge clean
forge fmt --check
forge test --match-path "contracts/test/*.t.sol" -vv
forge build --sizes
forge lint contracts/src contracts/test
slither . --foundry-compile-all --filter-paths "contracts/test" --fail-high
```

The dispatcher has no native-value send. The only native-value call occurs from a delegated wallet to its exact signed mint target, and the wallet's post-call balance must decrease by exactly the signed mint value.

The relevant artifacts are:

```text
contracts/out/SponsoredMintExecutor.sol/SponsoredMintExecutor.json
contracts/SponsoredMintExecutor.creation.hex
```

## Deployment verification

The release CLI deploys the sponsor-agnostic contract on the capability-probed chain derived from `RPC_URL`. It uses `SPONSOR_KEY`, estimates the factory call independently of the mint `GAS_LIMIT`, asks for explicit approval, submits bounded same-nonce replacements, and verifies the predicted address and deployed runtime hash:

```powershell
.\target\release\opensea-mint.exe deploy-executor
```

The command verifies the exact canonical deterministic factory runtime at `0x4e59b44847b379578588920cA78FbF26c0B4956C`, derives a domain-separated salt from the sponsor address, and submits `salt || creationCode`. The resulting `CREATE2` address is unique per sponsor and identical across supported chains. It accepts a clear EOA or exact EIP-7702 delegation designator as the payer, leaves that delegation unchanged, and verifies the executor at the receipt block. Missing or mismatched factory code, changed payer state, deterministic-address collisions, insufficient replacement funding, and runtime mismatch fail closed.

For independent verification, calculate `keccak256("opensea-mint/SponsoredMintExecutor/v1" || sponsor)` as the salt and pass `salt || contracts/SponsoredMintExecutor.creation.hex` to the canonical factory. The expected address follows the EIP-1014 formula using that salt and the creation-code hash below.

With the checked-in compiler profile, creation-code Keccak-256 is `0x6bcc55c2a44c46d8a3b24f71cef400d0fc38b611f6ec38acaaee24d71470bf4f`, and every compatible deployment must have runtime Keccak-256 `0x81a86fa2c51be4ed2e09e88256a792e20464184b657f49797d79c6eb90f63d60`.

Before configuring a deployment for use:

1. verify the exact Solidity version and `foundry.toml` settings;
2. publish and verify the source code;
3. compare `DISPATCHER()` with the deployed address;
4. compare `keccak256(eth_getCode(DISPATCHER))` with the expected runtime hash;
5. compare `DELEGATION_CODE_HASH()` with `keccak256(0xef0100 || DISPATCHER)`;
6. run a fork or supported-testnet EIP-7702 wallet-funded mint, sponsor replacement, failure isolation, and revocation; and
7. obtain an independent security audit before production use.

Dispatcher identity is derived from the execution context. Direct execution resolves to the deployed contract, while delegated execution parses the exact EIP-7702 designator. Signatures remain deployment-bound even though the runtime bytecode is universal.

The sponsor-bound signature schema is EIP-712 domain version `2`. Version `1` signatures and the previous constructor/API are intentionally incompatible and must not be accepted by the CLI.

## Primary references

- [EIP-7702: Set Code for EOAs](https://eips.ethereum.org/EIPS/eip-7702)
- [EIP-7997: Deterministic Factory Contract](https://eips.ethereum.org/EIPS/eip-7997)
- [EIP-1559: Type-2 transaction encoding](https://eips.ethereum.org/EIPS/eip-1559)
- [Ethereum Execution API: `eth_estimateGas`](https://ethereum.github.io/execution-apis/api/methods/eth_estimateGas/)
- [Ethereum Execution API: `eth_getTransactionReceipt`](https://ethereum.github.io/execution-apis/api/methods/eth_getTransactionReceipt/)
- [EIP-1153: Transient storage opcodes](https://eips.ethereum.org/EIPS/eip-1153)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [ERC-1271: Standard signature validation for contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [ERC-2098: Compact signature representation](https://eips.ethereum.org/EIPS/eip-2098)
- [ERC-721](https://eips.ethereum.org/EIPS/eip-721)
- [ERC-1155](https://eips.ethereum.org/EIPS/eip-1155)
- [OpenSea SeaDrop ERC-721 reference implementation](https://github.com/ProjectOpenSea/seadrop/blob/main/src/ERC721SeaDrop.sol)
- [OpenZeppelin EIP-7702 account guidance](https://docs.openzeppelin.com/contracts/5.x/accounts)
- [Foundry EIP-7702 delegation testing](https://getfoundry.sh/reference/cheatcodes/sign-delegation)

## License

This contract and the accompanying software are distributed under the [MIT License](../LICENSE).
