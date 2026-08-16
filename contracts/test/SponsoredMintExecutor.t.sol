// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {SponsoredMintExecutor} from "../src/SponsoredMintExecutor.sol";

interface Vm {
    struct SignedDelegation {
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint64 nonce;
        address implementation;
    }

    function attachDelegation(SignedDelegation calldata signedDelegation) external;
    function addr(uint256 privateKey) external returns (address);
    function chainId(uint256 newChainId) external;
    function deal(address account, uint256 newBalance) external;
    function etch(address target, bytes calldata newRuntimeBytecode) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function prank(address msgSender) external;
    function signCompact(uint256 privateKey, bytes32 digest) external returns (bytes32 r, bytes32 yParityAndS);
    function signDelegation(address implementation, uint256 privateKey)
        external
        returns (SignedDelegation memory signedDelegation);
    function warp(uint256 newTimestamp) external;
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

interface IERC1155Receiver {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        external
        returns (bytes4);

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

contract MockERC721Mint {
    mapping(uint256 tokenId => address owner) public ownerOf;
    uint256 public nextTokenId = 1;

    error InvalidOwner();
    error InvalidReceiver();

    function safeMint(address recipient, uint256 quantity) external payable {
        for (uint256 index; index < quantity;) {
            uint256 tokenId = nextTokenId++;
            ownerOf[tokenId] = recipient;
            if (recipient.code.length != 0) {
                bytes4 result = IERC721Receiver(recipient).onERC721Received(msg.sender, address(0), tokenId, "");
                if (result != IERC721Receiver.onERC721Received.selector) revert InvalidReceiver();
            }
            unchecked {
                ++index;
            }
        }
    }

    function safeTransferFrom(address from, address recipient, uint256 tokenId) external {
        if (ownerOf[tokenId] != from || msg.sender != from) revert InvalidOwner();
        ownerOf[tokenId] = recipient;
        if (recipient.code.length != 0) {
            bytes4 result = IERC721Receiver(recipient).onERC721Received(msg.sender, from, tokenId, "");
            if (result != IERC721Receiver.onERC721Received.selector) revert InvalidReceiver();
        }
    }
}

contract MockERC1155Mint {
    mapping(uint256 tokenId => mapping(address account => uint256 balance)) public balanceOf;

    error InsufficientBalance();
    error InvalidReceiver();
    error LengthMismatch();

    function mint(address recipient, uint256 tokenId, uint256 value) external payable {
        balanceOf[tokenId][recipient] += value;
        if (recipient.code.length != 0) {
            bytes4 result = IERC1155Receiver(recipient).onERC1155Received(msg.sender, address(0), tokenId, value, "");
            if (result != IERC1155Receiver.onERC1155Received.selector) revert InvalidReceiver();
        }
    }

    function mintBatch(address recipient, uint256[] calldata tokenIds, uint256[] calldata values) external payable {
        if (tokenIds.length != values.length) revert LengthMismatch();
        for (uint256 index; index < tokenIds.length;) {
            balanceOf[tokenIds[index]][recipient] += values[index];
            unchecked {
                ++index;
            }
        }
        if (recipient.code.length != 0) {
            bytes4 result =
                IERC1155Receiver(recipient).onERC1155BatchReceived(msg.sender, address(0), tokenIds, values, "");
            if (result != IERC1155Receiver.onERC1155BatchReceived.selector) revert InvalidReceiver();
        }
    }

    function safeTransferFrom(address from, address recipient, uint256 tokenId, uint256 value, bytes calldata data)
        external
    {
        if (msg.sender != from || balanceOf[tokenId][from] < value) revert InsufficientBalance();
        balanceOf[tokenId][from] -= value;
        balanceOf[tokenId][recipient] += value;
        if (recipient.code.length != 0) {
            bytes4 result = IERC1155Receiver(recipient).onERC1155Received(msg.sender, from, tokenId, value, data);
            if (result != IERC1155Receiver.onERC1155Received.selector) revert InvalidReceiver();
        }
    }

    function safeBatchTransferFrom(
        address from,
        address recipient,
        uint256[] calldata tokenIds,
        uint256[] calldata values,
        bytes calldata data
    ) external {
        if (msg.sender != from || tokenIds.length != values.length) {
            revert LengthMismatch();
        }
        for (uint256 index; index < tokenIds.length;) {
            uint256 tokenId = tokenIds[index];
            uint256 value = values[index];
            if (balanceOf[tokenId][from] < value) revert InsufficientBalance();
            balanceOf[tokenId][from] -= value;
            balanceOf[tokenId][recipient] += value;
            unchecked {
                ++index;
            }
        }
        if (recipient.code.length != 0) {
            bytes4 result = IERC1155Receiver(recipient).onERC1155BatchReceived(msg.sender, from, tokenIds, values, data);
            if (result != IERC1155Receiver.onERC1155BatchReceived.selector) revert InvalidReceiver();
        }
    }
}

contract RevertingMint {
    error DeliberateFailure();

    function mint() external payable {
        revert DeliberateFailure();
    }
}

contract ReturndataBombMint {
    function mint() external payable {
        assembly ("memory-safe") {
            mstore(0, 0xdeadbeef)
            revert(0, 0x10000)
        }
    }
}

contract RejectingERC721Recipient is IERC721Receiver {
    error Rejected();

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        revert Rejected();
    }
}

contract NonStandardERC721Mint {
    mapping(uint256 tokenId => address owner) public ownerOf;
    uint256 public nextTokenId = 1;

    error InvalidOwner();
    error InvalidReceiver();

    function safeMint(address recipient) external payable {
        uint256 tokenId = nextTokenId++;
        ownerOf[tokenId] = recipient;
        bytes4 result = IERC721Receiver(recipient).onERC721Received(msg.sender, address(0), tokenId, "");
        if (result != IERC721Receiver.onERC721Received.selector) revert InvalidReceiver();
    }

    function safeTransferFrom(address from, address recipient, uint256 tokenId) external returns (bool) {
        if (ownerOf[tokenId] != from || msg.sender != from) revert InvalidOwner();
        ownerOf[tokenId] = recipient;
        return false;
    }
}

contract DishonestERC721Mint {
    bool public callbackIssued;
    bool public transferPretended;

    function fakeMint(address recipient) external payable {
        callbackIssued = true;
        IERC721Receiver(recipient).onERC721Received(msg.sender, address(0), 1, "");
    }

    function safeTransferFrom(address, address, uint256) external {
        transferPretended = true;
    }
}

contract NativeTransferSender {
    error TransferFailed();

    function sendWithStipend(address payable recipient) external payable {
        (bool success,) = recipient.call{value: msg.value, gas: 2_300}("");
        if (!success) revert TransferFailed();
    }
}

contract OrdinaryCallRecorder {
    address public caller;
    uint256 public value;

    function record() external payable {
        caller = msg.sender;
        value = msg.value;
    }
}

contract SponsoredMintExecutorTest {
    Vm private constant _VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant _SPONSOR_KEY = 0xA11CE;
    uint256 private constant _WALLET_KEY = 0xB0B;
    uint256 private constant _SECOND_WALLET_KEY = 0xCAFE;
    uint64 private constant _MINT_GAS = 500_000;
    uint64 private constant _WALLET_GAS = 750_000;

    SponsoredMintExecutor private _executor;
    MockERC721Mint private _erc721;
    MockERC1155Mint private _erc1155;
    RevertingMint private _revertingMint;
    address private _sponsor;
    address private _wallet;
    address private _secondWallet;
    address private _recipient;

    function setUp() public {
        _sponsor = _VM.addr(_SPONSOR_KEY);
        _wallet = _VM.addr(_WALLET_KEY);
        _secondWallet = _VM.addr(_SECOND_WALLET_KEY);
        _recipient = address(0xBEEF);
        _executor = new SponsoredMintExecutor();
        _erc721 = new MockERC721Mint();
        _erc1155 = new MockERC1155Mint();
        _revertingMint = new RevertingMint();
        _delegate(_wallet);
        _delegate(_secondWallet);
        _VM.deal(_sponsor, 100 ether);
        _VM.warp(1_000_000);
    }

    function testSponsoredERC721MintForwardsEveryToken() public {
        bytes32 batchId = keccak256("erc721-success");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 2, 0.25 ether);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), operation.mintValue);

        _assertEq(_erc721.ownerOf(1), _recipient, "token 1 recipient");
        _assertEq(_erc721.ownerOf(2), _recipient, "token 2 recipient");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "batch must be consumed");
        _assertEq(address(_executor).balance, 0, "dispatcher must not retain ETH");
        _assertEq(_wallet.balance, 0, "delegated wallet must not retain mint ETH");
    }

    function testSuccessfulMintSpendsOnlySignedValueFromWalletBalance() public {
        bytes32 batchId = keccak256("wallet-funded-exact-value");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        _VM.deal(_wallet, 1 ether);
        uint256 sponsorBalanceBefore = _sponsor.balance;

        _execute(batchId, _single(operation), operation.mintValue);

        _assertEq(_wallet.balance, 0.75 ether, "wallet must spend only signed mint value");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_erc721.ownerOf(1), _recipient, "NFT recipient");
    }

    function testUnderfundedWalletFailsWithoutSpendingItsBalance() public {
        bytes32 batchId = keccak256("wallet-funded-insufficient-value");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        _VM.deal(_wallet, 0.24 ether);

        _VM.prank(_sponsor);
        _executor.executeBatch(batchId, _single(operation));

        _assertEq(_wallet.balance, 0.24 ether, "failed wallet balance must remain unchanged");
        _assertEq(_erc721.nextTokenId(), 1, "underfunded wallet must not mint");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "batch must be consumed");
    }

    function testRealEIP7702AuthorizationIsAppliedBeforeBatchExecution() public {
        uint256 freshWalletKey = 0x7702;
        address freshWallet = _VM.addr(freshWalletKey);
        bytes32 batchId = keccak256("real-eip7702-authorization");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(freshWallet, 1, 0);
        operation = _sign(operation, batchId, 0, freshWalletKey);

        Vm.SignedDelegation memory authorization = _VM.signDelegation(address(_executor), freshWalletKey);
        _VM.attachDelegation(authorization);
        _execute(batchId, _single(operation), 0);

        _assertEq(freshWallet.codehash, _executor.DELEGATION_CODE_HASH(), "authorization code hash");
        _assertEq(_erc721.ownerOf(1), _recipient, "authorized mint recipient");
    }

    function testRealEIP7702AuthorizationReplacesAnotherDelegateBeforeBatchExecution() public {
        uint256 walletKey = 0x7703;
        address wallet = _VM.addr(walletKey);
        Vm.SignedDelegation memory previousAuthorization = _VM.signDelegation(address(_erc721), walletKey);
        _VM.attachDelegation(previousAuthorization);
        _assertEq(
            wallet.codehash, keccak256(abi.encodePacked(hex"ef0100", address(_erc721))), "previous delegation code hash"
        );

        bytes32 batchId = keccak256("real-eip7702-replacement-authorization");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(wallet, 1, 0);
        operation = _sign(operation, batchId, 0, walletKey);
        Vm.SignedDelegation memory replacementAuthorization = _VM.signDelegation(address(_executor), walletKey);
        _VM.attachDelegation(replacementAuthorization);
        _execute(batchId, _single(operation), 0);

        _assertEq(wallet.codehash, _executor.DELEGATION_CODE_HASH(), "replacement delegation code hash");
        _assertEq(_erc721.ownerOf(1), _recipient, "replacement mint recipient");
    }

    function testSponsoredERC1155SingleMintForwardsUnits() public {
        bytes32 batchId = keccak256("erc1155-single");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet, address(_erc1155), address(_erc1155), abi.encodeCall(MockERC1155Mint.mint, (_wallet, 7, 4)), 4, 0
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc1155.balanceOf(7, _recipient), 4, "recipient units");
        _assertEq(_erc1155.balanceOf(7, _wallet), 0, "wallet units");
    }

    function testSponsoredERC1155BatchMintForwardsEveryUnit() public {
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 11;
        tokenIds[1] = 12;
        uint256[] memory values = new uint256[](2);
        values[0] = 2;
        values[1] = 3;

        bytes32 batchId = keccak256("erc1155-batch");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet,
            address(_erc1155),
            address(_erc1155),
            abi.encodeCall(MockERC1155Mint.mintBatch, (_wallet, tokenIds, values)),
            5,
            0
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc1155.balanceOf(11, _recipient), 2, "token 11 units");
        _assertEq(_erc1155.balanceOf(12, _recipient), 3, "token 12 units");
    }

    function testOneWalletFailurePreservesItsValueAndDoesNotRevertAnotherWallet() public {
        bytes32 batchId = keccak256("isolated-failure");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _baseOperation(
            _wallet, address(_revertingMint), address(_erc721), abi.encodeCall(RevertingMint.mint, ()), 1, 0.4 ether
        );
        operations[0] = _sign(operations[0], batchId, 0, _WALLET_KEY);
        operations[1] = _erc721Operation(_secondWallet, 1, 0.1 ether);
        operations[1] = _sign(operations[1], batchId, 1, _SECOND_WALLET_KEY);

        uint256 sponsorBalanceBefore = _sponsor.balance;
        _execute(batchId, operations, 0.5 ether);

        _assertEq(_erc721.ownerOf(1), _recipient, "second wallet must succeed");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.4 ether, "failed wallet must retain its mint value");
        _assertEq(address(_executor).balance, 0, "dispatcher must retain no ETH");
    }

    function testInvalidAuthorizationIsIsolatedAndPreservesWalletValue() public {
        address undelegatedWallet = _VM.addr(0xD00D);
        bytes32 batchId = keccak256("invalid-authorization-isolated");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _erc721Operation(undelegatedWallet, 1, 0.4 ether);
        operations[1] = _erc721Operation(_secondWallet, 1, 0.1 ether);
        operations[1] = _sign(operations[1], batchId, 1, _SECOND_WALLET_KEY);

        uint256 sponsorBalanceBefore = _sponsor.balance;
        _execute(batchId, operations, 0.5 ether);

        _assertEq(_erc721.ownerOf(1), _recipient, "valid wallet must still mint");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(undelegatedWallet.balance, 0.4 ether, "invalid wallet must retain its mint value");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "isolated batch must be consumed");
    }

    function testDuplicateWalletIsSkippedWithoutSpendingItsSecondMintValue() public {
        bytes32 batchId = keccak256("duplicate-wallet");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _sign(_erc721Operation(_wallet, 1, 0.1 ether), batchId, 0, _WALLET_KEY);
        operations[1] = _sign(_erc721Operation(_wallet, 1, 0.2 ether), batchId, 1, _WALLET_KEY);

        uint256 sponsorBalanceBefore = _sponsor.balance;
        _execute(batchId, operations, 0.3 ether);

        _assertEq(_erc721.nextTokenId(), 2, "only first wallet operation may mint");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.1 ether, "duplicate operation must not spend its value");

        bytes32 nextBatchId = keccak256("wallet-reusable-next-batch");
        SponsoredMintExecutor.MintOperation memory nextOperation =
            _sign(_erc721Operation(_wallet, 1, 0), nextBatchId, 0, _WALLET_KEY);
        _execute(nextBatchId, _single(nextOperation), 0);
        _assertEq(_erc721.nextTokenId(), 3, "duplicate marker must clear after batch");
    }

    function testMaximumBatchOfDistinctWalletsSucceeds() public {
        uint256 operationCount = _executor.MAX_BATCH_SIZE();
        bytes32 batchId = keccak256("maximum-distinct-wallet-batch");
        SponsoredMintExecutor.MintOperation[] memory operations =
            new SponsoredMintExecutor.MintOperation[](operationCount);

        for (uint256 index; index < operationCount;) {
            uint256 walletKey = 0x1000 + index;
            address wallet = _VM.addr(walletKey);
            _delegate(wallet);
            operations[index] = _sign(_erc721Operation(wallet, 1, 0), batchId, index, walletKey);
            unchecked {
                ++index;
            }
        }

        _execute(batchId, operations, 0);

        _assertEq(_erc721.nextTokenId(), operationCount + 1, "every maximum-batch wallet must mint");
    }

    function testLargeRevertDataCannotBreakFailureIsolation() public {
        ReturndataBombMint bomb = new ReturndataBombMint();
        bytes32 batchId = keccak256("returndata-bomb");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _baseOperation(
            _wallet, address(bomb), address(_erc721), abi.encodeCall(ReturndataBombMint.mint, ()), 1, 0.4 ether
        );
        operations[0] = _sign(operations[0], batchId, 0, _WALLET_KEY);
        operations[1] = _sign(_erc721Operation(_secondWallet, 1, 0.1 ether), batchId, 1, _SECOND_WALLET_KEY);

        uint256 sponsorBalanceBefore = _sponsor.balance;
        _execute(batchId, operations, 0.5 ether);

        _assertEq(_erc721.ownerOf(1), _recipient, "returndata bomb must not stop next wallet");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.4 ether, "failed wallet must retain its mint value");
    }

    function testForcedEtherDuringMintFailsClosedAndPreservesWalletValue() public {
        address forceTarget = address(0xF0CE);
        _VM.etch(forceTarget, abi.encodePacked(hex"73", _wallet, hex"ff"));
        bytes32 batchId = keccak256("forced-ether");
        SponsoredMintExecutor.MintOperation memory operation =
            _baseOperation(_wallet, forceTarget, address(_erc721), hex"12345678", 1, 0.4 ether);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        uint256 sponsorBalanceBefore = _sponsor.balance;
        _execute(batchId, _single(operation), 0.4 ether);

        _assertEq(_wallet.balance, 0.4 ether, "forced balance change must roll back");
        _assertEq(sponsorBalanceBefore, _sponsor.balance, "sponsor must pay no mint value");
    }

    function testForcedDispatcherEtherCannotBeDrainedByWalletFailure() public {
        address forceSender = address(0xF0CED);
        _VM.etch(forceSender, abi.encodePacked(hex"73", address(_executor), hex"ff"));
        _VM.deal(forceSender, 1 ether);
        (bool forced,) = forceSender.call("");
        _assertTrue(forced, "forced transfer must execute");

        bytes32 batchId = keccak256("forced-dispatcher-balance");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet, address(_revertingMint), address(_erc721), abi.encodeCall(RevertingMint.mint, ()), 1, 0.4 ether
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        uint256 sponsorBalanceBefore = _sponsor.balance;

        _execute(batchId, _single(operation), 0.4 ether);

        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(address(_executor).balance, 1 ether, "forced dispatcher ETH must remain isolated");
    }

    function testRejectingRecipientFailureIsIsolated() public {
        RejectingERC721Recipient rejectingRecipient = new RejectingERC721Recipient();
        bytes32 batchId = keccak256("rejecting-recipient");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _erc721Operation(_wallet, 1, 0);
        operations[0].recipient = address(rejectingRecipient);
        operations[0] = _sign(operations[0], batchId, 0, _WALLET_KEY);
        operations[1] = _sign(_erc721Operation(_secondWallet, 1, 0), batchId, 1, _SECOND_WALLET_KEY);

        _execute(batchId, operations, 0);

        _assertEq(_erc721.nextTokenId(), 2, "rejected mint must roll back before valid mint");
        _assertEq(_erc721.ownerOf(1), _recipient, "next wallet must receive its NFT");
    }

    function testNonStandardTokenTransferReturnFailsClosed() public {
        NonStandardERC721Mint token = new NonStandardERC721Mint();
        bytes32 batchId = keccak256("nonstandard-transfer-return");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet, address(token), address(token), abi.encodeCall(NonStandardERC721Mint.safeMint, (_wallet)), 1, 0
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(token.nextTokenId(), 1, "non-standard transfer must roll back mint");
        _assertEq(token.ownerOf(1), address(0), "wallet must not retain token");
    }

    function testSignedDishonestNftCanFakeSuccessWithinTrustBoundary() public {
        DishonestERC721Mint token = new DishonestERC721Mint();
        bytes32 batchId = keccak256("dishonest-nft-trust-boundary");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet,
            address(token),
            address(token),
            abi.encodeCall(DishonestERC721Mint.fakeMint, (_wallet)),
            1,
            0.2 ether
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0.2 ether);

        _assertTrue(token.callbackIssued(), "dishonest callback must execute");
        _assertTrue(token.transferPretended(), "dishonest transfer must execute");
        _assertEq(address(token).balance, 0.2 ether, "signed mint target receives value");
        _assertEq(_wallet.balance, 0, "wallet retains no mint value");
    }

    function testFuzzFailedWalletRetainsItsCompleteMintValue(uint96 rawValue) public {
        uint256 mintValue = uint256(rawValue) % 1 ether;
        bytes32 batchId = keccak256(abi.encode("fuzz-failed-value", mintValue));
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet, address(_revertingMint), address(_erc721), abi.encodeCall(RevertingMint.mint, ()), 1, mintValue
        );
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        uint256 sponsorBalanceBefore = _sponsor.balance;

        _execute(batchId, _single(operation), mintValue);

        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(address(_executor).balance, 0, "dispatcher balance invariant");
        _assertEq(_wallet.balance, mintValue, "failed wallet must retain its mint value");
    }

    function testTamperingWithSignedRecipientFailsClosed() public {
        bytes32 batchId = keccak256("tampered-recipient");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        operation.recipient = address(0xBAD);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "mint must not execute");
    }

    function testSignatureIsBoundToBatchId() public {
        bytes32 signedBatchId = keccak256("signed-batch");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, signedBatchId, 0, _WALLET_KEY);

        _execute(keccak256("different-batch"), _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "batch substitution must fail");
    }

    function testSignatureIsBoundToOperationIndex() public {
        bytes32 batchId = keccak256("signed-index");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 1, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "index substitution must fail");
    }

    function testSignatureIsBoundToChainId() public {
        bytes32 batchId = keccak256("signed-chain");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        _VM.chainId(block.chainid + 1);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "cross-chain replay must fail");
    }

    function testSignatureIsBoundToDispatcherDeployment() public {
        bytes32 batchId = keccak256("signed-dispatcher");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        SponsoredMintExecutor otherExecutor = new SponsoredMintExecutor();
        _VM.etch(_wallet, abi.encodePacked(hex"ef0100", address(otherExecutor)));

        _VM.prank(_sponsor);
        otherExecutor.executeBatch(batchId, _single(operation));

        _assertEq(_erc721.nextTokenId(), 1, "cross-deployment replay must fail");
    }

    function testRuntimeBytecodeIsIdenticalAcrossDeployments() public {
        uint256 originalChainId = block.chainid;
        _VM.chainId(originalChainId + 1);
        SponsoredMintExecutor otherExecutor = new SponsoredMintExecutor();
        _VM.chainId(originalChainId);

        _assertEq(
            uint256(address(_executor).codehash),
            uint256(address(otherExecutor).codehash),
            "runtime code must be universal"
        );
        _assertEq(
            uint256(address(_executor).codehash),
            uint256(keccak256(type(SponsoredMintExecutor).runtimeCode)),
            "deployed code must match the build artifact"
        );
        _assertEq(_executor.DISPATCHER(), address(_executor), "first dispatcher context");
        _assertEq(otherExecutor.DISPATCHER(), address(otherExecutor), "second dispatcher context");
    }

    function testDelegatedContextResolvesTheActualDispatcher() public view {
        SponsoredMintExecutor delegatedWallet = SponsoredMintExecutor(payable(_wallet));

        _assertEq(delegatedWallet.DISPATCHER(), address(_executor), "delegated dispatcher");
        _assertEq(delegatedWallet.DELEGATION_CODE_HASH(), _wallet.codehash, "delegated code hash");
    }

    function testLegacyVersionOneSignatureFailsClosed() public {
        bytes32 batchId = keccak256("legacy-version-one");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        bytes32 legacyDigest = _legacyOperationDigest(operation, batchId, 0);
        (operation.signatureR, operation.signatureYParityAndS) = _VM.signCompact(_WALLET_KEY, legacyDigest);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "legacy signature must not mint");
    }

    function testDigestBindsEveryOperationField() public view {
        bytes32 batchId = keccak256("complete-digest-binding");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0.25 ether);
        bytes32 originalDigest = _executor.operationDigest(_wallet, _sponsor, batchId, 0, operation);

        _assertDigestChanges(originalDigest, _secondWallet, _sponsor, batchId, 0, operation, "account");
        _assertDigestChanges(originalDigest, _wallet, address(0xDADA), batchId, 0, operation, "sponsor");
        _assertDigestChanges(originalDigest, _wallet, _sponsor, keccak256("other-batch"), 0, operation, "batch");
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 1, operation, "index");

        operation.wallet = _secondWallet;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "wallet");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.mintTarget = address(_erc1155);
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "mint target");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.nftContract = address(_erc1155);
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "NFT contract");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.recipient = address(0xCA11);
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "recipient");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.mintValue += 1;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "mint value");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.expectedUnits += 1;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "expected units");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.mintGasLimit += 1;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "mint gas");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.walletGasLimit += 1;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "wallet gas");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.deadline += 1;
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "deadline");
        operation = _erc721Operation(_wallet, 1, 0.25 ether);
        operation.mintCalldata[operation.mintCalldata.length - 1] ^= bytes1(uint8(1));
        _assertDigestChanges(originalDigest, _wallet, _sponsor, batchId, 0, operation, "mint calldata");
    }

    function testHighSCompactSignatureFailsClosed() public {
        bytes32 batchId = keccak256("high-s");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation.signatureR = bytes32(uint256(1));
        operation.signatureYParityAndS = bytes32(0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "malleable signature must fail");
    }

    function testWrongSignerFailsClosed() public {
        bytes32 batchId = keccak256("wrong-signer");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _SECOND_WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "mint must not execute");
    }

    function testExpiredOperationFailsClosed() public {
        bytes32 batchId = keccak256("expired");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation.deadline = uint48(block.timestamp - 1);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "expired mint must not execute");
    }

    function testUnsafeGasShapeFailsOnlyThatWallet() public {
        bytes32 batchId = keccak256("under-gassed");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation.walletGasLimit = operation.mintGasLimit + 1;
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "invalid gas shape must prevent mint");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "isolated failure batch must be consumed");
    }

    function testEip150ClampedWalletGasIsSkippedWithoutStoppingBatch() public {
        bytes32 batchId = keccak256("eip150-wallet-gas-clamp");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _erc721Operation(_wallet, 1, 0.4 ether);
        operations[0].walletGasLimit = type(uint64).max;
        operations[0] = _sign(operations[0], batchId, 0, _WALLET_KEY);
        operations[1] = _sign(_erc721Operation(_secondWallet, 1, 0.1 ether), batchId, 1, _SECOND_WALLET_KEY);
        uint256 sponsorBalanceBefore = _sponsor.balance;

        _execute(batchId, operations, 0.5 ether);

        _assertEq(_erc721.nextTokenId(), 2, "only exactly gas-bounded wallet may mint");
        _assertEq(_erc721.ownerOf(1), _recipient, "later wallet recipient");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.4 ether, "skipped wallet must retain its mint value");
    }

    function testExecutorSelfTargetCannotSpoofMintSuccess() public {
        bytes32 batchId = keccak256("executor-self-target-spoof");
        bytes memory fakeCallback =
            abi.encodeCall(SponsoredMintExecutor.onERC721Received, (address(0), address(0), uint256(1), bytes("")));
        SponsoredMintExecutor.MintOperation memory operation =
            _baseOperation(_wallet, _wallet, _wallet, fakeCallback, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _VM.expectRevert(abi.encodeWithSelector(SponsoredMintExecutor.TargetIsExecutor.selector, _wallet));
        _VM.prank(address(_executor));
        SponsoredMintExecutor(payable(_wallet)).executeSponsoredMint(_sponsor, batchId, 0, operation);
    }

    function testOversizedMintCalldataFailsOnlyThatWallet() public {
        bytes32 batchId = keccak256("oversized-mint-calldata");
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](2);

        operations[0] = _erc721Operation(_wallet, 1, 0.4 ether);
        operations[0].mintCalldata = new bytes(_executor.MAX_MINT_CALLDATA_SIZE() + 1);
        operations[0] = _sign(operations[0], batchId, 0, _WALLET_KEY);
        operations[1] = _sign(_erc721Operation(_secondWallet, 1, 0.1 ether), batchId, 1, _SECOND_WALLET_KEY);
        uint256 sponsorBalanceBefore = _sponsor.balance;

        _execute(batchId, operations, 0.5 ether);

        _assertEq(_erc721.nextTokenId(), 2, "oversized calldata must not stop later wallet");
        _assertEq(_erc721.ownerOf(1), _recipient, "later wallet recipient");
        _assertEq(_sponsor.balance, sponsorBalanceBefore, "sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.4 ether, "skipped wallet must retain its mint value");
    }

    function testMalformedOperationsDoNotStopValidWallet() public {
        uint256 operationCount = 6;
        bytes32 batchId = keccak256("malformed-operations-isolated");
        SponsoredMintExecutor.MintOperation[] memory operations =
            new SponsoredMintExecutor.MintOperation[](operationCount);

        for (uint256 index; index < operationCount;) {
            uint256 walletKey = 0x6000 + index;
            address wallet = _VM.addr(walletKey);
            _delegate(wallet);
            operations[index] = _erc721Operation(wallet, 1, 0);
            unchecked {
                ++index;
            }
        }
        operations[0].mintTarget = address(0);
        operations[1].mintCalldata = hex"1234";
        operations[2].expectedUnits = 0;
        operations[3].recipient = operations[3].wallet;
        operations[4].mintGasLimit = 0;

        for (uint256 index; index < operationCount;) {
            operations[index] = _sign(operations[index], batchId, index, 0x6000 + index);
            unchecked {
                ++index;
            }
        }

        _execute(batchId, operations, 0);

        _assertEq(_erc721.nextTokenId(), 2, "only structurally valid wallet may mint");
        _assertEq(_erc721.ownerOf(1), _recipient, "valid final wallet recipient");
    }

    function testReplayOfBatchIdReverts() public {
        bytes32 batchId = keccak256("replay");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);
        SponsoredMintExecutor.MintOperation[] memory operations = _single(operation);

        _execute(batchId, operations, 0);
        _VM.expectRevert(SponsoredMintExecutor.BatchAlreadyUsed.selector);
        _execute(batchId, operations, 0);
    }

    function testDifferentSponsorCannotConsumeSignedSponsorsBatch() public {
        address otherSponsor = _VM.addr(0xDADA);
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        bytes32 batchId = keccak256("sponsor-namespace-isolation");
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _VM.prank(otherSponsor);
        _executor.executeBatch(batchId, _single(operation));

        _assertEq(_erc721.nextTokenId(), 1, "different sponsor signature must fail");
        _assertTrue(_executor.isBatchUsed(otherSponsor, batchId), "caller's namespace must be consumed");
        _assertTrue(!_executor.isBatchUsed(_sponsor, batchId), "signed sponsor namespace must remain unused");

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.ownerOf(1), _recipient, "signed sponsor must still execute");
    }

    function testSponsorCanChangeWithoutRedeploymentOrRedelegation() public {
        address otherSponsor = _VM.addr(0xDADA);
        bytes32 batchId = keccak256("shared-batch-id-across-sponsors");
        bytes32 delegationHashBefore = _wallet.codehash;

        SponsoredMintExecutor.MintOperation memory firstOperation = _erc721Operation(_wallet, 1, 0);
        firstOperation = _sign(firstOperation, batchId, 0, _WALLET_KEY);
        _execute(batchId, _single(firstOperation), 0);

        SponsoredMintExecutor.MintOperation memory secondOperation = _erc721Operation(_wallet, 1, 0);
        secondOperation = _signForSponsor(secondOperation, otherSponsor, batchId, 0, _WALLET_KEY);
        _executeAs(otherSponsor, batchId, _single(secondOperation), 0);

        _assertEq(_erc721.ownerOf(1), _recipient, "first sponsor mint");
        _assertEq(_erc721.ownerOf(2), _recipient, "replacement sponsor mint");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "first sponsor replay key");
        _assertTrue(_executor.isBatchUsed(otherSponsor, batchId), "replacement sponsor replay key");
        _assertEq(_wallet.codehash, delegationHashBefore, "delegation must remain unchanged");
    }

    function testReplacementSponsorPaysNoMintValueWhenWalletFails() public {
        address otherSponsor = _VM.addr(0xDADA);
        bytes32 batchId = keccak256("replacement-sponsor-refund");
        SponsoredMintExecutor.MintOperation memory operation = _baseOperation(
            _wallet, address(_revertingMint), address(_erc721), abi.encodeCall(RevertingMint.mint, ()), 1, 0.4 ether
        );
        operation = _signForSponsor(operation, otherSponsor, batchId, 0, _WALLET_KEY);
        _VM.deal(otherSponsor, 1 ether);
        uint256 balanceBefore = otherSponsor.balance;

        _executeAs(otherSponsor, batchId, _single(operation), 0.4 ether);

        _assertEq(otherSponsor.balance, balanceBefore, "replacement sponsor must pay no mint value");
        _assertEq(_wallet.balance, 0.4 ether, "failed wallet must retain its mint value");
        _assertEq(address(_executor).balance, 0, "dispatcher must retain no ETH");
        _assertTrue(_executor.isBatchUsed(otherSponsor, batchId), "replacement sponsor replay key");
    }

    function testWrongDelegationFailsOnlyThatWallet() public {
        address undelegatedWallet = _VM.addr(0xD00D);
        bytes32 batchId = keccak256("wrong-delegation");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(undelegatedWallet, 1, 0);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "wrong delegation must not mint");
        _assertTrue(_executor.isBatchUsed(_sponsor, batchId), "wrong delegation batch must be consumed");
    }

    function testSponsorCannotSupplyMintValueToBatch() public {
        bytes32 batchId = keccak256("sponsor-value-rejected");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 1 ether);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _VM.prank(_sponsor);
        (bool success,) = address(_executor).call{value: 0.5 ether}(
            abi.encodeCall(SponsoredMintExecutor.executeBatch, (batchId, _single(operation)))
        );
        _assertTrue(!success, "nonzero sponsor value must be rejected");
        _assertTrue(!_executor.isBatchUsed(_sponsor, batchId), "rejected value must not consume batch");
    }

    function testDirectWalletExecutionCannotBypassDispatcher() public {
        bytes32 batchId = keccak256("direct-call");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _VM.prank(_sponsor);
        _VM.expectRevert(SponsoredMintExecutor.DispatcherContextRequired.selector);
        SponsoredMintExecutor(payable(_wallet)).executeSponsoredMint(_sponsor, batchId, 0, operation);
    }

    function testDelegatedWalletCannotActAsTheBatchDispatcher() public {
        SponsoredMintExecutor.MintOperation[] memory operations = new SponsoredMintExecutor.MintOperation[](0);

        _VM.prank(_sponsor);
        _VM.expectRevert(SponsoredMintExecutor.DispatcherContextRequired.selector);
        SponsoredMintExecutor(payable(_wallet)).executeBatch(bytes32(uint256(1)), operations);
    }

    function testDelegatedWalletAcceptsPlainEtherAndUnknownCalldata() public {
        _VM.deal(address(this), 1 ether);

        (bool emptyCallSucceeded,) = payable(_wallet).call{value: 0.25 ether}("");
        (bool dataCallSucceeded, bytes memory returnData) = payable(_wallet).call{value: 0.5 ether}(hex"deadbeef0102");

        _assertTrue(emptyCallSucceeded, "plain ETH receipt");
        _assertTrue(dataCallSucceeded, "unknown calldata receipt");
        _assertEq(returnData.length, 0, "EOA-like empty returndata");
        _assertEq(_wallet.balance, 0.75 ether, "delegated wallet balance");
    }

    function testDelegatedWalletAcceptsNativeTransferWithStipend() public {
        NativeTransferSender sender = new NativeTransferSender();

        sender.sendWithStipend{value: 0.25 ether}(payable(_wallet));

        _assertEq(_wallet.balance, 0.25 ether, "stipend transfer balance");
    }

    function testDispatcherRejectsPlainEtherAndUnknownCalldata() public {
        _VM.deal(address(this), 1 ether);

        (bool emptyCallSucceeded,) = payable(address(_executor)).call{value: 0.25 ether}("");
        (bool dataCallSucceeded,) = payable(address(_executor)).call{value: 0.5 ether}(hex"deadbeef0102");

        _assertTrue(!emptyCallSucceeded, "dispatcher plain ETH must fail");
        _assertTrue(!dataCallSucceeded, "dispatcher unknown calldata must fail");
        _assertEq(address(_executor).balance, 0, "dispatcher must not retain ETH");
    }

    function testDelegatedWalletOriginatesOrdinaryTransaction() public {
        OrdinaryCallRecorder recorder = new OrdinaryCallRecorder();
        _VM.deal(_wallet, 1 ether);

        _VM.prank(_wallet);
        recorder.record{value: 0.25 ether}();

        _assertEq(recorder.caller(), _wallet, "ordinary call sender");
        _assertEq(recorder.value(), 0.25 ether, "ordinary call value");
        _assertEq(_wallet.balance, 0.75 ether, "ordinary call wallet balance");
    }

    function testDelegatedWalletAcceptsUnsolicitedERC721() public {
        _erc721.safeMint(_recipient, 1);
        _VM.prank(_recipient);
        _erc721.safeTransferFrom(_recipient, _wallet, 1);

        _assertEq(_erc721.ownerOf(1), _wallet, "wallet must retain passive ERC721 receipt");
    }

    function testDispatcherRejectsUnsolicitedERC721() public {
        _VM.expectRevert(SponsoredMintExecutor.DelegatedContextRequired.selector);
        _erc721.safeMint(address(_executor), 1);
    }

    function testDelegatedWalletAcceptsUnsolicitedERC1155() public {
        _erc1155.mint(_wallet, 7, 4);

        _assertEq(_erc1155.balanceOf(7, _wallet), 4, "wallet must retain passive ERC1155 receipt");
    }

    function testDelegatedWalletAcceptsUnsolicitedERC1155Batch() public {
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 7;
        tokenIds[1] = 8;
        uint256[] memory values = new uint256[](2);
        values[0] = 4;
        values[1] = 5;

        _erc1155.mintBatch(_wallet, tokenIds, values);

        _assertEq(_erc1155.balanceOf(7, _wallet), 4, "first passive ERC1155 receipt");
        _assertEq(_erc1155.balanceOf(8, _wallet), 5, "second passive ERC1155 receipt");
    }

    function testERC1271AcceptsCompactAndCanonicalWalletSignatures() public {
        bytes32 digest = keccak256("erc1271-valid-signature");
        (bytes32 r, bytes32 yParityAndS) = _VM.signCompact(_WALLET_KEY, digest);
        bytes memory compactSignature = abi.encodePacked(r, yParityAndS);

        uint256 compactS = uint256(yParityAndS);
        bytes32 s = bytes32(compactS & ((1 << 255) - 1));
        uint8 v = compactS >> 255 == 0 ? 27 : 28;
        bytes memory canonicalSignature = abi.encodePacked(r, s, v);

        _assertEq(
            uint256(uint32(SponsoredMintExecutor(payable(_wallet)).isValidSignature(digest, compactSignature))),
            uint256(uint32(0x1626ba7e)),
            "compact signature"
        );
        _assertEq(
            uint256(uint32(SponsoredMintExecutor(payable(_wallet)).isValidSignature(digest, canonicalSignature))),
            uint256(uint32(0x1626ba7e)),
            "canonical signature"
        );
    }

    function testERC1271RejectsWrongSignerAndMalformedSignature() public {
        bytes32 digest = keccak256("erc1271-invalid-signature");
        (bytes32 r, bytes32 yParityAndS) = _VM.signCompact(_SECOND_WALLET_KEY, digest);

        _assertEq(
            uint256(
                uint32(
                    SponsoredMintExecutor(payable(_wallet)).isValidSignature(digest, abi.encodePacked(r, yParityAndS))
                )
            ),
            uint256(uint32(0xffffffff)),
            "wrong signer"
        );
        _assertEq(
            uint256(uint32(SponsoredMintExecutor(payable(_wallet)).isValidSignature(digest, hex"1234"))),
            uint256(uint32(0xffffffff)),
            "malformed signature"
        );
    }

    function testERC1271RejectsHighSAndInvalidV() public view {
        bytes32 digest = keccak256("erc1271-non-canonical-signature");
        bytes32 r = bytes32(uint256(1));
        bytes32 highS = bytes32(0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1);

        _assertEq(
            uint256(
                uint32(
                    SponsoredMintExecutor(payable(_wallet))
                        .isValidSignature(digest, abi.encodePacked(r, highS, uint8(27)))
                )
            ),
            uint256(uint32(0xffffffff)),
            "high-s signature"
        );
        _assertEq(
            uint256(
                uint32(
                    SponsoredMintExecutor(payable(_wallet))
                        .isValidSignature(digest, abi.encodePacked(r, bytes32(uint256(1)), uint8(29)))
                )
            ),
            uint256(uint32(0xffffffff)),
            "invalid v"
        );
    }

    function testExpectedQuantityMismatchRevertsWalletMint() public {
        bytes32 batchId = keccak256("quantity-mismatch");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 1, 0);
        operation.expectedUnits = 2;
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "mint state must roll back");
    }

    function testExtraMintUnitsRevertWalletOperation() public {
        bytes32 batchId = keccak256("extra-mint-units");
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, 2, 0);
        operation.expectedUnits = 1;
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        _assertEq(_erc721.nextTokenId(), 1, "extra units must roll back complete wallet mint");
    }

    function testEmptyAndOversizedBatchesRevert() public {
        SponsoredMintExecutor.MintOperation[] memory empty = new SponsoredMintExecutor.MintOperation[](0);
        _VM.prank(_sponsor);
        _VM.expectRevert(SponsoredMintExecutor.BatchSizeInvalid.selector);
        _executor.executeBatch(keccak256("empty"), empty);

        SponsoredMintExecutor.MintOperation[] memory oversized =
            new SponsoredMintExecutor.MintOperation[](_executor.MAX_BATCH_SIZE() + 1);
        _VM.prank(_sponsor);
        _VM.expectRevert(SponsoredMintExecutor.BatchSizeInvalid.selector);
        _executor.executeBatch(keccak256("oversized"), oversized);
    }

    function testInterfaceSupportIsNarrow() public view {
        _assertTrue(_executor.supportsInterface(0x01ffc9a7), "ERC165");
        _assertTrue(_executor.supportsInterface(0x150b7a02), "ERC721 receiver");
        _assertTrue(_executor.supportsInterface(0x4e2312e0), "ERC1155 receiver");
        _assertTrue(!_executor.supportsInterface(0xffffffff), "unknown interface");
    }

    function testFuzzSignedMintQuantity(uint8 rawQuantity) public {
        uint256 quantity = uint256(rawQuantity % 8) + 1;
        bytes32 batchId = keccak256(abi.encode("fuzz-quantity", quantity));
        SponsoredMintExecutor.MintOperation memory operation = _erc721Operation(_wallet, quantity, 0);
        operation = _sign(operation, batchId, 0, _WALLET_KEY);

        _execute(batchId, _single(operation), 0);

        for (uint256 tokenId = 1; tokenId <= quantity;) {
            _assertEq(_erc721.ownerOf(tokenId), _recipient, "fuzz token recipient");
            unchecked {
                ++tokenId;
            }
        }
    }

    function _erc721Operation(address wallet, uint256 quantity, uint256 mintValue)
        private
        view
        returns (SponsoredMintExecutor.MintOperation memory)
    {
        return _baseOperation(
            wallet,
            address(_erc721),
            address(_erc721),
            abi.encodeCall(MockERC721Mint.safeMint, (wallet, quantity)),
            quantity,
            mintValue
        );
    }

    function _baseOperation(
        address wallet,
        address mintTarget,
        address nftContract,
        bytes memory mintCalldata,
        uint256 expectedUnits,
        uint256 mintValue
    ) private view returns (SponsoredMintExecutor.MintOperation memory) {
        return SponsoredMintExecutor.MintOperation({
            wallet: wallet,
            mintTarget: mintTarget,
            nftContract: nftContract,
            recipient: _recipient,
            mintValue: mintValue,
            expectedUnits: expectedUnits,
            mintGasLimit: _MINT_GAS,
            walletGasLimit: _WALLET_GAS,
            deadline: uint48(block.timestamp + 1 hours),
            mintCalldata: mintCalldata,
            signatureR: bytes32(0),
            signatureYParityAndS: bytes32(0)
        });
    }

    function _sign(
        SponsoredMintExecutor.MintOperation memory operation,
        bytes32 batchId,
        uint256 index,
        uint256 privateKey
    ) private returns (SponsoredMintExecutor.MintOperation memory) {
        return _signForSponsor(operation, _sponsor, batchId, index, privateKey);
    }

    function _signForSponsor(
        SponsoredMintExecutor.MintOperation memory operation,
        address sponsor,
        bytes32 batchId,
        uint256 index,
        uint256 privateKey
    ) private returns (SponsoredMintExecutor.MintOperation memory) {
        bytes32 digest = _executor.operationDigest(operation.wallet, sponsor, batchId, index, operation);
        (operation.signatureR, operation.signatureYParityAndS) = _VM.signCompact(privateKey, digest);
        return operation;
    }

    function _legacyOperationDigest(
        SponsoredMintExecutor.MintOperation memory operation,
        bytes32 batchId,
        uint256 index
    ) private view returns (bytes32) {
        bytes32 domainTypeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                domainTypeHash, keccak256("OSNM-Z Sponsored Mint"), keccak256("1"), block.chainid, operation.wallet
            )
        );
        bytes32 legacyTypeHash = keccak256(
            "SponsoredMint(bytes32 batchId,uint256 index,address dispatcher,address wallet,address mintTarget,bytes32 mintCalldataHash,uint256 mintValue,uint256 expectedUnits,uint64 mintGasLimit,uint64 walletGasLimit,address nftContract,address recipient,uint48 deadline)"
        );
        bytes32 structHash = keccak256(
            abi.encode(
                legacyTypeHash,
                batchId,
                index,
                address(_executor),
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

    function _delegate(address wallet) private {
        _VM.etch(wallet, abi.encodePacked(hex"ef0100", address(_executor)));
        _assertEq(wallet.codehash, _executor.DELEGATION_CODE_HASH(), "delegation hash");
    }

    function _assertDigestChanges(
        bytes32 originalDigest,
        address account,
        address sponsor,
        bytes32 batchId,
        uint256 index,
        SponsoredMintExecutor.MintOperation memory operation,
        string memory reason
    ) private view {
        bytes32 changedDigest = _executor.operationDigest(account, sponsor, batchId, index, operation);
        require(changedDigest != originalDigest, reason);
    }

    function _execute(
        bytes32 batchId,
        SponsoredMintExecutor.MintOperation[] memory operations,
        uint256 expectedWalletMintValue
    ) private {
        _executeAs(_sponsor, batchId, operations, expectedWalletMintValue);
    }

    function _executeAs(
        address sponsor,
        bytes32 batchId,
        SponsoredMintExecutor.MintOperation[] memory operations,
        uint256 expectedWalletMintValue
    ) private {
        uint256 configuredWalletMintValue = 0;
        for (uint256 index; index < operations.length; ++index) {
            address wallet = operations[index].wallet;
            uint256 mintValue = operations[index].mintValue;
            configuredWalletMintValue += mintValue;
            if (wallet.balance < mintValue) _VM.deal(wallet, mintValue);
        }
        _assertEq(configuredWalletMintValue, expectedWalletMintValue, "test fixture wallet mint value");
        _VM.prank(sponsor);
        _executor.executeBatch(batchId, operations);
    }

    function _single(SponsoredMintExecutor.MintOperation memory operation)
        private
        pure
        returns (SponsoredMintExecutor.MintOperation[] memory operations)
    {
        operations = new SponsoredMintExecutor.MintOperation[](1);
        operations[0] = operation;
    }

    function _assertTrue(bool value, string memory reason) private pure {
        require(value, reason);
    }

    function _assertEq(address actual, address expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertEq(bytes32 actual, bytes32 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }
}
