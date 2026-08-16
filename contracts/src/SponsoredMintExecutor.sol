// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/**
 *  @notice Narrow EIP-7702 executor for sponsored NFT mints and immediate forwarding.
 */
contract SponsoredMintExecutor {
    /**
     * @notice Fully signed parameters for one isolated wallet mint.
     */
    struct MintOperation {
        address wallet;
        address mintTarget;
        address nftContract;
        address recipient;
        uint256 mintValue;
        uint256 expectedUnits;
        uint64 mintGasLimit;
        uint64 walletGasLimit;
        uint48 deadline;
        bytes mintCalldata;
        bytes32 signatureR;
        bytes32 signatureYParityAndS;
    }

    uint256 public constant MAX_BATCH_SIZE = 25;
    uint256 public constant MAX_MINT_CALLDATA_SIZE = 16_384;
    uint256 private constant _POST_MINT_GAS_RESERVE = 25_000;
    uint256 private constant _FINAL_BATCH_GAS_RESERVE = 50_000;
    uint256 private constant _PER_REMAINING_OPERATION_GAS_RESERVE = 30_000;
    uint256 private constant _SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant _DELEGATION_CODE_SIZE = 23;
    uint256 private constant _DELEGATION_PREFIX = 0xef0100;

    bytes32 public constant MINT_OPERATION_TYPEHASH = keccak256(
        "SponsoredMint(address sponsor,bytes32 batchId,uint256 index,address dispatcher,address wallet,address mintTarget,bytes32 mintCalldataHash,uint256 mintValue,uint256 expectedUnits,uint64 mintGasLimit,uint64 walletGasLimit,address nftContract,address recipient,uint48 deadline)"
    );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _NAME_HASH = keccak256("OSNM-Z Sponsored Mint");
    bytes32 private constant _VERSION_HASH = keccak256("2");
    bytes32 private constant _BATCH_GUARD_SLOT = keccak256("osnm-z.sponsored-mint.batch-guard.v1");
    bytes32 private constant _MINT_ACTIVE_SLOT = keccak256("osnm-z.sponsored-mint.active.v1");
    bytes32 private constant _MINT_NFT_SLOT = keccak256("osnm-z.sponsored-mint.nft.v1");
    bytes32 private constant _MINT_RECIPIENT_SLOT = keccak256("osnm-z.sponsored-mint.recipient.v1");
    bytes32 private constant _MINT_EXPECTED_SLOT = keccak256("osnm-z.sponsored-mint.expected.v1");
    bytes32 private constant _MINT_FORWARDED_SLOT = keccak256("osnm-z.sponsored-mint.forwarded.v1");
    bytes32 private constant _SEEN_WALLET_NAMESPACE = keccak256("osnm-z.sponsored-mint.seen-wallet.v1");

    bytes4 private constant _ERC721_RECEIVED = 0x150b7a02;
    bytes4 private constant _ERC1155_RECEIVED = 0xf23a6e61;
    bytes4 private constant _ERC1155_BATCH_RECEIVED = 0xbc197c81;
    bytes4 private constant _ERC165_INTERFACE = 0x01ffc9a7;
    bytes4 private constant _ERC1155_RECEIVER_INTERFACE = 0x4e2312e0;
    bytes4 private constant _ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _ERC1271_INVALID_SIGNATURE = 0xffffffff;
    bytes4 private constant _ERC721_SAFE_TRANSFER_FROM = 0x42842e0e;
    bytes4 private constant _ERC1155_SAFE_TRANSFER_FROM = 0xf242432a;
    bytes4 private constant _ERC1155_SAFE_BATCH_TRANSFER_FROM = 0x2eb2c2d6;

    mapping(bytes32 batchKey => bool used) private _usedBatches;

    event WalletExecution(
        bytes32 indexed batchId,
        address indexed sponsor,
        address indexed wallet,
        uint256 index,
        bool success,
        bytes4 errorSelector
    );

    error BatchAlreadyUsed();
    error BatchIdInvalid();
    error BatchSizeInvalid();
    error CalldataTooLarge();
    error DelegatedContextRequired();
    error DispatcherContextRequired();
    error DuplicateWallet();
    error EmptyCalldata();
    error ExpectedUnitsInvalid();
    error GasLimitInvalid();
    error InsufficientExecutionGas();
    error InvalidDelegation();
    error InvalidSignature();
    error MintCallFailed(bytes4 errorSelector);
    error MintResultMismatch(uint256 expected, uint256 forwarded);
    error InsufficientMintBalance(uint256 required, uint256 available);
    error MintBalanceMismatch(uint256 expected, uint256 actual);
    error OperationExpired();
    error ReentrantCall();
    error RecipientEqualsWallet();
    error TargetHasNoCode(address target);
    error TargetIsExecutor(address target);
    error TokenCallbackInvalid();
    error TokenForwardFailed(bytes4 errorSelector);
    error TokenForwardInvalidReturnData(uint256 size);
    error ZeroAddress();

    /**
     * @notice Returns the implementation selected by the current execution context.
     */
    function DISPATCHER() external view returns (address) {
        (, address dispatcher) = _executionContext();
        return dispatcher;
    }

    /**
     * @notice Returns the EIP-7702 designator hash for the current dispatcher.
     */
    function DELEGATION_CODE_HASH() external view returns (bytes32) {
        (, address dispatcher) = _executionContext();
        return _delegationCodeHash(dispatcher);
    }

    /**
     * @notice Preserves ordinary native-token receipt while an EOA remains delegated.
     */
    receive() external payable {
        (bool delegated,) = _executionContext();
        if (!delegated) revert DelegatedContextRequired();
    }

    /**
     * @notice Gives delegated EOAs the empty-success behavior of an EOA for unknown calls.
     */
    fallback() external payable {
        (bool delegated,) = _executionContext();
        if (!delegated) revert DelegatedContextRequired();
    }

    /**
     * @notice Executes a gas-sponsored batch whose wallets fund their signed mint values.
     */
    function executeBatch(bytes32 batchId, MintOperation[] calldata operations) external {
        (bool delegated, address dispatcher) = _executionContext();
        if (delegated) revert DispatcherContextRequired();
        if (batchId == bytes32(0)) revert BatchIdInvalid();

        address payable sponsor = payable(msg.sender);
        bytes32 batchKey = _batchKey(sponsor, batchId);
        uint256 operationCount = operations.length;
        if (operationCount == 0 || operationCount > MAX_BATCH_SIZE) revert BatchSizeInvalid();
        if (_usedBatches[batchKey]) revert BatchAlreadyUsed();
        if (_transientLoad(_BATCH_GUARD_SLOT) != 0) revert ReentrantCall();

        _usedBatches[batchKey] = true;
        _transientStore(_BATCH_GUARD_SLOT, 1);

        /*
         * Batch-scoped markers preserve sequential calls without an O(n) cleanup loop.
         */
        uint256 batchMarker = uint256(batchKey);
        bytes32 delegationCodeHash = _delegationCodeHash(dispatcher);
        for (uint256 index; index < operationCount;) {
            MintOperation calldata operation = operations[index];
            bytes32 seenWalletSlot = _seenWalletSlot(operation.wallet);
            bool success = false;
            bytes4 errorSelector = bytes4(0);

            if (operation.wallet == address(0) || operation.wallet.codehash != delegationCodeHash) {
                errorSelector = InvalidDelegation.selector;
            } else if (_transientLoad(seenWalletSlot) == batchMarker) {
                errorSelector = DuplicateWallet.selector;
            } else {
                _transientStore(seenWalletSlot, batchMarker);
                if (operation.mintCalldata.length > MAX_MINT_CALLDATA_SIZE) {
                    errorSelector = CalldataTooLarge.selector;
                } else {
                    bytes memory payload =
                        abi.encodeCall(this.executeSponsoredMint, (sponsor, batchId, index, operation));
                    uint256 remainingOperations = operationCount - index - 1;
                    uint256 continuationGas =
                        _FINAL_BATCH_GAS_RESERVE + remainingOperations * _PER_REMAINING_OPERATION_GAS_RESERVE;

                    if (!_canForwardExactGas(operation.walletGasLimit, continuationGas)) {
                        errorSelector = InsufficientExecutionGas.selector;
                    } else {
                        (success, errorSelector,) =
                            _callWithoutReturndataCopy(operation.wallet, 0, operation.walletGasLimit, payload);
                    }
                }
            }
            emit WalletExecution(batchId, sponsor, operation.wallet, index, success, errorSelector);
            unchecked {
                ++index;
            }
        }

        _transientStore(_BATCH_GUARD_SLOT, 0);
    }

    /**
     * @notice Performs one signed mint from a delegated EOA execution context.
     */
    function executeSponsoredMint(address sponsor, bytes32 batchId, uint256 index, MintOperation calldata operation)
        external
    {
        (bool delegated, address dispatcher) = _executionContext();
        if (!delegated) revert DelegatedContextRequired();
        if (msg.sender != dispatcher) revert DispatcherContextRequired();
        if (operation.wallet != address(this)) revert InvalidDelegation();
        _validateOperationShape(operation, dispatcher);
        if (block.timestamp > operation.deadline) revert OperationExpired();
        if (gasleft() < uint256(operation.mintGasLimit) + _POST_MINT_GAS_RESERVE) {
            revert InsufficientExecutionGas();
        }

        bytes32 digest = _operationDigest(address(this), dispatcher, sponsor, batchId, index, operation);
        if (!_isValidCompactSignature(digest, operation.signatureR, operation.signatureYParityAndS)) {
            revert InvalidSignature();
        }
        if (_transientLoad(_MINT_ACTIVE_SLOT) != 0) revert ReentrantCall();

        uint256 balanceBeforeMint = address(this).balance;
        if (balanceBeforeMint < operation.mintValue) {
            revert InsufficientMintBalance(operation.mintValue, balanceBeforeMint);
        }
        uint256 expectedBalanceAfterMint = balanceBeforeMint - operation.mintValue;
        _transientStore(_MINT_NFT_SLOT, uint256(uint160(operation.nftContract)));
        _transientStore(_MINT_RECIPIENT_SLOT, uint256(uint160(operation.recipient)));
        _transientStore(_MINT_EXPECTED_SLOT, operation.expectedUnits);
        _transientStore(_MINT_FORWARDED_SLOT, 0);
        _transientStore(_MINT_ACTIVE_SLOT, 1);

        bytes memory mintCalldata = operation.mintCalldata;
        bool success;
        bytes4 errorSelector;
        uint256 mintGasLimit = operation.mintGasLimit;
        address mintTarget = operation.mintTarget;
        uint256 mintValue = operation.mintValue;
        assembly ("memory-safe") {
            success := call(mintGasLimit, mintTarget, mintValue, add(mintCalldata, 0x20), mload(mintCalldata), 0, 0)
            if and(iszero(success), gt(returndatasize(), 3)) {
                returndatacopy(0, 0, 4)
                errorSelector := mload(0)
            }
        }
        if (!success) revert MintCallFailed(errorSelector);
        uint256 balanceAfterMint = address(this).balance;
        if (balanceAfterMint != expectedBalanceAfterMint) {
            revert MintBalanceMismatch(expectedBalanceAfterMint, balanceAfterMint);
        }

        uint256 forwarded = _transientLoad(_MINT_FORWARDED_SLOT);
        if (forwarded != operation.expectedUnits) {
            revert MintResultMismatch(operation.expectedUnits, forwarded);
        }
        _clearMintContext();
    }

    /**
     * @notice Computes the exact EIP-712 digest that the wallet must sign.
     */
    function operationDigest(
        address account,
        address sponsor,
        bytes32 batchId,
        uint256 index,
        MintOperation calldata operation
    ) public view returns (bytes32) {
        (, address dispatcher) = _executionContext();
        return _operationDigest(account, dispatcher, sponsor, batchId, index, operation);
    }

    function _operationDigest(
        address account,
        address dispatcher,
        address sponsor,
        bytes32 batchId,
        uint256 index,
        MintOperation calldata operation
    ) private view returns (bytes32) {
        bytes32 domainSeparator =
            keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, account));
        bytes32 structHash = keccak256(
            abi.encode(
                MINT_OPERATION_TYPEHASH,
                sponsor,
                batchId,
                index,
                dispatcher,
                operation.wallet,
                operation.mintTarget,
                keccak256(operation.mintCalldata),
                operation.mintValue,
                operation.expectedUnits,
                operation.mintGasLimit,
                operation.walletGasLimit,
                operation.nftContract,
                operation.recipient,
                operation.deadline
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /**
     * @notice Returns whether one sponsor has permanently consumed a batch ID.
     */
    function isBatchUsed(address sponsor, bytes32 batchId) external view returns (bool) {
        return _usedBatches[_batchKey(sponsor, batchId)];
    }

    /**
     * @notice Reports only ERC-165 and the supported NFT receiver interfaces.
     */
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == _ERC165_INTERFACE || interfaceId == _ERC721_RECEIVED
            || interfaceId == _ERC1155_RECEIVER_INTERFACE;
    }

    /**
     * @notice Validates ordinary compact or canonical ECDSA signatures for ERC-1271 callers.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length == 64) {
            bytes32 yParityAndS;
            assembly ("memory-safe") {
                r := calldataload(signature.offset)
                yParityAndS := calldataload(add(signature.offset, 0x20))
            }
            uint256 compactS = uint256(yParityAndS);
            s = bytes32(compactS & ((1 << 255) - 1));
            v = compactS >> 255 == 0 ? 27 : 28;
        } else if (signature.length == 65) {
            assembly ("memory-safe") {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 0x20))
                v := byte(0, calldataload(add(signature.offset, 0x40)))
            }
            if (v < 27) v += 27;
        } else {
            return _ERC1271_INVALID_SIGNATURE;
        }

        return _isValidRecoveredSignature(hash, r, s, v) ? _ERC1271_MAGIC_VALUE : _ERC1271_INVALID_SIGNATURE;
    }

    /**
     * @notice Forwards an expected ERC-721 safe mint to the signed recipient.
     */
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata) external returns (bytes4) {
        if (_acceptPassiveTokenReceipt()) return _ERC721_RECEIVED;
        _validateTokenCallback(from);
        uint256 forwarded = _transientLoad(_MINT_FORWARDED_SLOT) + 1;
        if (forwarded > _transientLoad(_MINT_EXPECTED_SLOT)) revert TokenCallbackInvalid();
        _transientStore(_MINT_FORWARDED_SLOT, forwarded);

        bytes memory transferData =
            abi.encodeWithSelector(_ERC721_SAFE_TRANSFER_FROM, address(this), _mintRecipient(), tokenId);
        _forwardToken(msg.sender, transferData);
        return _ERC721_RECEIVED;
    }

    /**
     * @notice Forwards an expected ERC-1155 safe mint to the signed recipient.
     */
    function onERC1155Received(address, address from, uint256 tokenId, uint256 value, bytes calldata)
        external
        returns (bytes4)
    {
        if (_acceptPassiveTokenReceipt()) return _ERC1155_RECEIVED;
        _validateTokenCallback(from);
        if (value == 0) revert TokenCallbackInvalid();
        _increaseForwarded(value);

        bytes memory transferData = abi.encodeWithSelector(
            _ERC1155_SAFE_TRANSFER_FROM, address(this), _mintRecipient(), tokenId, value, bytes("")
        );
        _forwardToken(msg.sender, transferData);
        return _ERC1155_RECEIVED;
    }

    /**
     * @notice Forwards an expected ERC-1155 batch mint to the signed recipient.
     */
    function onERC1155BatchReceived(
        address,
        address from,
        uint256[] calldata tokenIds,
        uint256[] calldata values,
        bytes calldata
    ) external returns (bytes4) {
        if (_acceptPassiveTokenReceipt()) return _ERC1155_BATCH_RECEIVED;
        _validateTokenCallback(from);
        uint256 itemCount = tokenIds.length;
        if (itemCount == 0 || itemCount != values.length) revert TokenCallbackInvalid();

        uint256 units = 0;
        for (uint256 index; index < itemCount;) {
            uint256 value = values[index];
            if (value == 0) revert TokenCallbackInvalid();
            units += value;
            unchecked {
                ++index;
            }
        }
        _increaseForwarded(units);

        bytes memory transferData = abi.encodeWithSelector(
            _ERC1155_SAFE_BATCH_TRANSFER_FROM, address(this), _mintRecipient(), tokenIds, values, bytes("")
        );
        _forwardToken(msg.sender, transferData);
        return _ERC1155_BATCH_RECEIVED;
    }

    function _validateOperationShape(MintOperation calldata operation, address dispatcher) private view {
        if (
            operation.wallet == address(0) || operation.mintTarget == address(0) || operation.nftContract == address(0)
                || operation.recipient == address(0)
        ) revert ZeroAddress();
        if (operation.recipient == operation.wallet) revert RecipientEqualsWallet();
        if (operation.mintCalldata.length < 4) revert EmptyCalldata();
        if (operation.mintCalldata.length > MAX_MINT_CALLDATA_SIZE) revert CalldataTooLarge();
        if (operation.expectedUnits == 0) revert ExpectedUnitsInvalid();
        if (
            operation.mintGasLimit == 0
                || uint256(operation.walletGasLimit) < uint256(operation.mintGasLimit) + _POST_MINT_GAS_RESERVE
        ) {
            revert GasLimitInvalid();
        }
        if (operation.mintTarget.code.length == 0) revert TargetHasNoCode(operation.mintTarget);
        if (operation.nftContract.code.length == 0) revert TargetHasNoCode(operation.nftContract);
        if (operation.mintTarget == operation.wallet || operation.mintTarget == dispatcher) {
            revert TargetIsExecutor(operation.mintTarget);
        }
        if (operation.nftContract == operation.wallet || operation.nftContract == dispatcher) {
            revert TargetIsExecutor(operation.nftContract);
        }
    }

    function _validateTokenCallback(address from) private view {
        if (
            _transientLoad(_MINT_ACTIVE_SLOT) == 0 || from != address(0)
                || msg.sender != address(uint160(_transientLoad(_MINT_NFT_SLOT)))
        ) revert TokenCallbackInvalid();
    }

    function _acceptPassiveTokenReceipt() private view returns (bool) {
        if (_transientLoad(_MINT_ACTIVE_SLOT) != 0) return false;
        (bool delegated,) = _executionContext();
        if (!delegated) revert DelegatedContextRequired();
        return true;
    }

    function _executionContext() private view returns (bool delegated, address dispatcher) {
        if (address(this).code.length != _DELEGATION_CODE_SIZE) return (false, address(this));

        bytes memory accountCode = address(this).code;
        uint256 prefix;
        assembly ("memory-safe") {
            prefix := shr(232, mload(add(accountCode, 0x20)))
            dispatcher := shr(96, mload(add(accountCode, 0x23)))
        }
        if (prefix != _DELEGATION_PREFIX || dispatcher == address(0)) return (false, address(this));
        return (true, dispatcher);
    }

    function _delegationCodeHash(address dispatcher) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"ef0100", dispatcher));
    }

    function _increaseForwarded(uint256 units) private {
        uint256 forwarded = _transientLoad(_MINT_FORWARDED_SLOT) + units;
        if (forwarded > _transientLoad(_MINT_EXPECTED_SLOT)) revert TokenCallbackInvalid();
        _transientStore(_MINT_FORWARDED_SLOT, forwarded);
    }

    function _mintRecipient() private view returns (address) {
        return address(uint160(_transientLoad(_MINT_RECIPIENT_SLOT)));
    }

    function _forwardToken(address token, bytes memory transferData) private {
        (bool success, bytes4 errorSelector, uint256 returnDataSize) =
            _callWithoutReturndataCopy(token, 0, gasleft(), transferData);
        if (!success) revert TokenForwardFailed(errorSelector);
        if (returnDataSize != 0) revert TokenForwardInvalidReturnData(returnDataSize);
    }

    function _clearMintContext() private {
        _transientStore(_MINT_ACTIVE_SLOT, 0);
        _transientStore(_MINT_NFT_SLOT, 0);
        _transientStore(_MINT_RECIPIENT_SLOT, 0);
        _transientStore(_MINT_EXPECTED_SLOT, 0);
        _transientStore(_MINT_FORWARDED_SLOT, 0);
    }

    function _isValidCompactSignature(bytes32 digest, bytes32 r, bytes32 yParityAndS) private view returns (bool) {
        uint256 compactS = uint256(yParityAndS);
        bytes32 s = bytes32(compactS & ((1 << 255) - 1));
        uint8 v = compactS >> 255 == 0 ? 27 : 28;
        return _isValidRecoveredSignature(digest, r, s, v);
    }

    function _isValidRecoveredSignature(bytes32 digest, bytes32 r, bytes32 s, uint8 v) private view returns (bool) {
        if (r == bytes32(0) || s == bytes32(0) || uint256(s) > _SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            return false;
        }
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == address(this);
    }

    function _seenWalletSlot(address wallet) private pure returns (bytes32 slot) {
        bytes32 namespace = _SEEN_WALLET_NAMESPACE;
        assembly ("memory-safe") {
            mstore(0, namespace)
            mstore(0x20, shl(96, wallet))
            slot := keccak256(0, 0x34)
        }
    }

    function _batchKey(address sponsor, bytes32 batchId) private pure returns (bytes32 key) {
        assembly ("memory-safe") {
            mstore(0, sponsor)
            mstore(0x20, batchId)
            key := keccak256(0, 0x40)
        }
    }

    function _canForwardExactGas(uint256 gasLimit, uint256 continuationGas) private view returns (bool) {
        /*
         * EIP-150 retains 1/64 of call gas; this buffer prevents silent clamping.
         */
        uint256 eip150Buffer = (gasLimit + 62) / 63;
        return gasleft() >= gasLimit + eip150Buffer + continuationGas;
    }

    function _callWithoutReturndataCopy(address target, uint256 value, uint256 gasLimit, bytes memory data)
        private
        returns (bool success, bytes4 errorSelector, uint256 returnDataSize)
    {
        assembly ("memory-safe") {
            success := call(gasLimit, target, value, add(data, 0x20), mload(data), 0, 0)
            returnDataSize := returndatasize()
            if and(iszero(success), gt(returndatasize(), 3)) {
                returndatacopy(0, 0, 4)
                errorSelector := mload(0)
            }
        }
    }

    function _transientLoad(bytes32 slot) private view returns (uint256 value) {
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }

    function _transientStore(bytes32 slot, uint256 value) private {
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }
}
