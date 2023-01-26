
pragma solidity ^0.8.0;

interface IERC20 {

    function totalSupply() external view returns (uint256);


    function balanceOf(address account) external view returns (uint256);


    function transfer(address recipient, uint256 amount) external returns (bool);


    function allowance(address owner, address spender) external view returns (uint256);


    function approve(address spender, uint256 amount) external returns (bool);


    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}// MIT

pragma solidity ^0.8.0;

library Address {

    function isContract(address account) internal view returns (bool) {


        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

      return functionCall(target, data, "Address: low-level call failed");
    }

    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {

        return functionCallWithValue(target, data, 0, errorMessage);
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {

        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {

        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {

        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {

        if (success) {
            return returndata;
        } else {
            if (returndata.length > 0) {

                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}// MIT

pragma solidity ^0.8.0;


library SafeERC20 {

    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {


        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) { // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}// MIT

pragma solidity =0.8.3;

library Orders {

    bytes32 internal constant ASK_TYPEHASH = 0x5fbc9a24e1532fa5245d1ec2dc5592849ae97ac5475f361b1a1f7a6e2ac9b2fd;
    bytes32 internal constant BID_TYPEHASH = 0xb98e1dc48988064e6dfb813618609d7da80a8841e5f277039788ac4b50d497b2;

    struct Ask {
        address signer;
        address proxy;
        address token;
        uint256 tokenId;
        uint256 amount;
        address strategy;
        address currency;
        address recipient;
        uint256 deadline;
        bytes params;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct Bid {
        bytes32 askHash;
        address signer;
        uint256 amount;
        uint256 price;
        address recipient;
        address referrer;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    function hash(Ask memory ask) internal pure returns (bytes32) {

        return
            keccak256(
                abi.encode(
                    ASK_TYPEHASH,
                    ask.signer,
                    ask.proxy,
                    ask.token,
                    ask.tokenId,
                    ask.amount,
                    ask.strategy,
                    ask.currency,
                    ask.recipient,
                    ask.deadline,
                    keccak256(ask.params)
                )
            );
    }

    function hash(Bid memory bid) internal pure returns (bytes32) {

        return
            keccak256(
                abi.encode(BID_TYPEHASH, bid.askHash, bid.signer, bid.amount, bid.price, bid.recipient, bid.referrer)
            );
    }
}// MIT

pragma solidity >=0.5.0;


interface IBaseExchange {

    event Cancel(bytes32 indexed hash);
    event Claim(
        bytes32 indexed hash,
        address bidder,
        uint256 amount,
        uint256 price,
        address recipient,
        address referrer
    );
    event Bid(bytes32 indexed hash, address bidder, uint256 amount, uint256 price, address recipient, address referrer);
    event UpdateApprovedBidHash(
        address indexed proxy,
        bytes32 indexed askHash,
        address indexed bidder,
        bytes32 bidHash
    );

    function DOMAIN_SEPARATOR() external view returns (bytes32);


    function factory() external view returns (address);


    function canTrade(address token) external view returns (bool);


    function bestBid(bytes32 hash)
        external
        view
        returns (
            address bidder,
            uint256 amount,
            uint256 price,
            address recipient,
            address referrer,
            uint256 blockNumber
        );


    function isCancelledOrClaimed(bytes32 hash) external view returns (bool);


    function amountFilled(bytes32 hash) external view returns (uint256);


    function approvedBidHash(
        address proxy,
        bytes32 askHash,
        address bidder
    ) external view returns (bytes32 bidHash);


    function cancel(Orders.Ask memory order) external;


    function updateApprovedBidHash(
        bytes32 askHash,
        address bidder,
        bytes32 bidHash
    ) external;


    function bid(Orders.Ask memory askOrder, Orders.Bid memory bidOrder) external returns (bool executed);


    function bid(
        Orders.Ask memory askOrder,
        uint256 bidAmount,
        uint256 bidPrice,
        address bidRecipient,
        address bidReferrer
    ) external returns (bool executed);


    function claim(Orders.Ask memory order) external;

}// MIT

pragma solidity >=0.5.0;

interface ITokenFactory {

    event SetBaseURI721(string uri);
    event SetBaseURI1155(string uri);
    event SetProtocolFeeRecipient(address recipient);
    event SetOperationalFee(uint8 fee);
    event SetOperationalFeeRecipient(address recipient);
    event SetDeployerWhitelisted(address deployer, bool whitelisted);
    event SetStrategyWhitelisted(address strategy, bool whitelisted);
    event UpgradeNFT721(address newTarget);
    event UpgradeNFT1155(address newTarget);
    event UpgradeSocialToken(address newTarget);
    event UpgradeERC721Exchange(address exchange);
    event UpgradeERC1155Exchange(address exchange);
    event DeployNFT721AndMintBatch(
        address indexed proxy,
        address indexed owner,
        string name,
        string symbol,
        uint256[] tokenIds,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    );
    event DeployNFT721AndPark(
        address indexed proxy,
        address indexed owner,
        string name,
        string symbol,
        uint256 toTokenId,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    );
    event DeployNFT1155AndMintBatch(
        address indexed proxy,
        address indexed owner,
        uint256[] tokenIds,
        uint256[] amounts,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    );
    event DeploySocialToken(
        address indexed proxy,
        address indexed owner,
        string name,
        string symbol,
        address indexed dividendToken,
        uint256 initialSupply
    );

    function MAX_ROYALTY_FEE() external view returns (uint8);


    function MAX_OPERATIONAL_FEE() external view returns (uint8);


    function PARK_TOKEN_IDS_721_TYPEHASH() external view returns (bytes32);


    function MINT_BATCH_721_TYPEHASH() external view returns (bytes32);


    function MINT_BATCH_1155_TYPEHASH() external view returns (bytes32);


    function MINT_SOCIAL_TOKEN_TYPEHASH() external view returns (bytes32);


    function DOMAIN_SEPARATOR() external view returns (bytes32);


    function nonces(address account) external view returns (uint256);


    function baseURI721() external view returns (string memory);


    function baseURI1155() external view returns (string memory);


    function erc721Exchange() external view returns (address);


    function erc1155Exchange() external view returns (address);


    function protocolFeeInfo() external view returns (address recipient, uint8 permil);


    function operationalFeeInfo() external view returns (address recipient, uint8 permil);


    function isStrategyWhitelisted(address strategy) external view returns (bool);


    function isDeployerWhitelisted(address strategy) external view returns (bool);


    function setBaseURI721(string memory uri) external;


    function setBaseURI1155(string memory uri) external;


    function setProtocolFeeRecipient(address protocolFeeRecipient) external;


    function setOperationalFeeRecipient(address operationalFeeRecipient) external;


    function setOperationalFee(uint8 operationalFee) external;


    function setDeployerWhitelisted(address deployer, bool whitelisted) external;


    function setStrategyWhitelisted(address strategy, bool whitelisted) external;


    function upgradeNFT721(address newTarget) external;


    function upgradeNFT1155(address newTarget) external;


    function upgradeSocialToken(address newTarget) external;


    function upgradeERC721Exchange(address exchange) external;


    function upgradeERC1155Exchange(address exchange) external;


    function deployNFT721AndMintBatch(
        address owner,
        string calldata name,
        string calldata symbol,
        uint256[] calldata tokenIds,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external returns (address nft);


    function deployNFT721AndPark(
        address owner,
        string calldata name,
        string calldata symbol,
        uint256 toTokenId,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external returns (address nft);


    function isNFT721(address query) external view returns (bool result);


    function deployNFT1155AndMintBatch(
        address owner,
        uint256[] memory tokenIds,
        uint256[] memory amounts,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external returns (address nft);


    function isNFT1155(address query) external view returns (bool result);


    function deploySocialToken(
        address owner,
        string memory name,
        string memory symbol,
        address dividendToken,
        uint256 initialSupply
    ) external returns (address proxy);


    function isSocialToken(address query) external view returns (bool result);


    function parkTokenIds721(
        address nft,
        uint256 toTokenId,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;


    function mintBatch721(
        address nft,
        address to,
        uint256[] calldata tokenIds,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;


    function mintBatch1155(
        address nft,
        address to,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;


    function mintSocialToken(
        address token,
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

}// MIT

pragma solidity >=0.5.0;


interface IStrategy {

    function canClaim(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address bidder,
        uint256 bidPrice,
        address bestBidder,
        uint256 bestBidPrice,
        uint256 bestBidTimestamp
    ) external view returns (bool);


    function canBid(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address bidder,
        uint256 bidPrice,
        address bestBidder,
        uint256 bestBidPrice,
        uint256 bestBidTimestamp
    ) external view returns (bool);

}// MIT

pragma solidity ^0.8.0;


interface IERC20Metadata is IERC20 {

    function name() external view returns (string memory);


    function symbol() external view returns (string memory);


    function decimals() external view returns (uint8);

}// MIT

pragma solidity >=0.5.0;


interface IDividendPayingERC20 is IERC20, IERC20Metadata {

    event Sync(uint256 increased);

    event DividendWithdrawn(address indexed to, uint256 amount);

    function MAGNITUDE() external view returns (uint256);


    function dividendToken() external view returns (address);


    function totalDividend() external view returns (uint256);


    function sync() external payable returns (uint256 increased);


    function withdrawDividend() external;


    function dividendOf(address account) external view returns (uint256);


    function withdrawableDividendOf(address account) external view returns (uint256);


    function withdrawnDividendOf(address account) external view returns (uint256);


    function accumulativeDividendOf(address account) external view returns (uint256);

}// MIT

pragma solidity ^0.8.0;

abstract contract Initializable {

    bool private _initialized;

    bool private _initializing;

    modifier initializer() {
        require(_initializing || !_initialized, "Initializable: contract is already initialized");

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }
}// MIT

pragma solidity =0.8.3;


abstract contract ReentrancyGuardInitializable is Initializable {

    bool private constant _NOT_ENTERED = false;
    bool private constant _ENTERED = true;

    bool private _status;

    function __ReentrancyGuard_init() internal initializer {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal initializer {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "SHOYU: REENTRANT");

        _status = _ENTERED;

        _;

        _status = _NOT_ENTERED;
    }
}// MIT
pragma solidity >=0.5.0;

interface IERC1271 {

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);

}// MIT

pragma solidity =0.8.3;


library Signature {

    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {

        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "SHOYU: INVALID_SIGNATURE_S_VALUE"
        );
        require(v == 27 || v == 28, "SHOYU: INVALID_SIGNATURE_V_VALUE");

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "SHOYU: INVALID_SIGNATURE");

        return signer;
    }

    function verify(
        bytes32 hash,
        address signer,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 domainSeparator
    ) internal view {

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, hash));
        if (Address.isContract(signer)) {
            require(
                IERC1271(signer).isValidSignature(digest, abi.encodePacked(r, s, v)) == 0x1626ba7e,
                "SHOYU: UNAUTHORIZED"
            );
        } else {
            require(recover(digest, v, r, s) == signer, "SHOYU: UNAUTHORIZED");
        }
    }
}// MIT

pragma solidity ^0.8.0;

interface IERC165 {

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

}// MIT

pragma solidity =0.8.3;


interface IERC2981 is IERC165 {


    function royaltyInfo(uint256 _tokenId, uint256 _salePrice)
        external
        view
        returns (address receiver, uint256 royaltyAmount);

}// MIT

pragma solidity =0.8.3;



abstract contract BaseExchange is ReentrancyGuardInitializable, IBaseExchange {
    using SafeERC20 for IERC20;
    using Orders for Orders.Ask;
    using Orders for Orders.Bid;

    struct BestBid {
        address bidder;
        uint256 amount;
        uint256 price;
        address recipient;
        address referrer;
        uint256 timestamp;
    }

    mapping(address => mapping(bytes32 => mapping(address => bytes32))) internal _bidHashes;

    mapping(bytes32 => BestBid) public override bestBid;
    mapping(bytes32 => bool) public override isCancelledOrClaimed;
    mapping(bytes32 => uint256) public override amountFilled;

    function __BaseNFTExchange_init() internal initializer {
        __ReentrancyGuard_init();
    }

    function DOMAIN_SEPARATOR() public view virtual override returns (bytes32);

    function factory() public view virtual override returns (address);

    function canTrade(address token) public view virtual override returns (bool) {
        return token == address(this);
    }

    function approvedBidHash(
        address proxy,
        bytes32 askHash,
        address bidder
    ) external view override returns (bytes32 bidHash) {
        return _bidHashes[proxy][askHash][bidder];
    }

    function _transfer(
        address token,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) internal virtual;

    function cancel(Orders.Ask memory order) external override {
        require(order.signer == msg.sender || order.proxy == msg.sender, "SHOYU: FORBIDDEN");

        bytes32 hash = order.hash();
        require(bestBid[hash].bidder == address(0), "SHOYU: BID_EXISTS");

        isCancelledOrClaimed[hash] = true;

        emit Cancel(hash);
    }

    function updateApprovedBidHash(
        bytes32 askHash,
        address bidder,
        bytes32 bidHash
    ) external override {
        _bidHashes[msg.sender][askHash][bidder] = bidHash;
        emit UpdateApprovedBidHash(msg.sender, askHash, bidder, bidHash);
    }

    function bid(Orders.Ask memory askOrder, Orders.Bid memory bidOrder)
        external
        override
        nonReentrant
        returns (bool executed)
    {
        bytes32 askHash = askOrder.hash();
        require(askHash == bidOrder.askHash, "SHOYU: UNMATCHED_HASH");
        require(bidOrder.signer != address(0), "SHOYU: INVALID_SIGNER");

        bytes32 bidHash = bidOrder.hash();
        if (askOrder.proxy != address(0)) {
            require(
                askOrder.proxy == msg.sender || _bidHashes[askOrder.proxy][askHash][bidOrder.signer] == bidHash,
                "SHOYU: FORBIDDEN"
            );
            delete _bidHashes[askOrder.proxy][askHash][bidOrder.signer];
            emit UpdateApprovedBidHash(askOrder.proxy, askHash, bidOrder.signer, bytes32(0));
        }

        Signature.verify(bidHash, bidOrder.signer, bidOrder.v, bidOrder.r, bidOrder.s, DOMAIN_SEPARATOR());

        return
            _bid(
                askOrder,
                askHash,
                bidOrder.signer,
                bidOrder.amount,
                bidOrder.price,
                bidOrder.recipient,
                bidOrder.referrer
            );
    }

    function bid(
        Orders.Ask memory askOrder,
        uint256 bidAmount,
        uint256 bidPrice,
        address bidRecipient,
        address bidReferrer
    ) external override nonReentrant returns (bool executed) {
        require(askOrder.proxy == address(0), "SHOYU: FORBIDDEN");

        return _bid(askOrder, askOrder.hash(), msg.sender, bidAmount, bidPrice, bidRecipient, bidReferrer);
    }

    function _bid(
        Orders.Ask memory askOrder,
        bytes32 askHash,
        address bidder,
        uint256 bidAmount,
        uint256 bidPrice,
        address bidRecipient,
        address bidReferrer
    ) internal returns (bool executed) {
        require(canTrade(askOrder.token), "SHOYU: INVALID_EXCHANGE");
        require(bidAmount > 0, "SHOYU: INVALID_AMOUNT");
        uint256 _amountFilled = amountFilled[askHash];
        require(_amountFilled + bidAmount <= askOrder.amount, "SHOYU: SOLD_OUT");

        _validate(askOrder, askHash);
        Signature.verify(askHash, askOrder.signer, askOrder.v, askOrder.r, askOrder.s, DOMAIN_SEPARATOR());

        BestBid storage best = bestBid[askHash];
        if (
            IStrategy(askOrder.strategy).canClaim(
                askOrder.proxy,
                askOrder.deadline,
                askOrder.params,
                bidder,
                bidPrice,
                best.bidder,
                best.price,
                best.timestamp
            )
        ) {
            amountFilled[askHash] = _amountFilled + bidAmount;
            if (_amountFilled + bidAmount == askOrder.amount) isCancelledOrClaimed[askHash] = true;

            address recipient = askOrder.recipient;
            if (recipient == address(0)) recipient = askOrder.signer;
            require(
                _transferFeesAndFunds(
                    askOrder.token,
                    askOrder.tokenId,
                    askOrder.currency,
                    bidder,
                    recipient,
                    bidPrice * bidAmount
                ),
                "SHOYU: FAILED_TO_TRANSFER_FUNDS"
            );

            if (bidRecipient == address(0)) bidRecipient = bidder;
            _transfer(askOrder.token, askOrder.signer, bidRecipient, askOrder.tokenId, bidAmount);

            emit Claim(askHash, bidder, bidAmount, bidPrice, bidRecipient, bidReferrer);
            return true;
        } else {
            if (
                IStrategy(askOrder.strategy).canBid(
                    askOrder.proxy,
                    askOrder.deadline,
                    askOrder.params,
                    bidder,
                    bidPrice,
                    best.bidder,
                    best.price,
                    best.timestamp
                )
            ) {
                best.bidder = bidder;
                best.amount = bidAmount;
                best.price = bidPrice;
                best.recipient = bidRecipient;
                best.referrer = bidReferrer;
                best.timestamp = block.timestamp;

                emit Bid(askHash, bidder, bidAmount, bidPrice, bidRecipient, bidReferrer);
                return false;
            }
        }
        revert("SHOYU: FAILURE");
    }

    function claim(Orders.Ask memory askOrder) external override nonReentrant {
        require(canTrade(askOrder.token), "SHOYU: INVALID_EXCHANGE");

        bytes32 askHash = askOrder.hash();
        _validate(askOrder, askHash);
        Signature.verify(askHash, askOrder.signer, askOrder.v, askOrder.r, askOrder.s, DOMAIN_SEPARATOR());

        BestBid memory best = bestBid[askHash];
        require(
            IStrategy(askOrder.strategy).canClaim(
                askOrder.proxy,
                askOrder.deadline,
                askOrder.params,
                best.bidder,
                best.price,
                best.bidder,
                best.price,
                best.timestamp
            ),
            "SHOYU: FAILURE"
        );

        address recipient = askOrder.recipient;
        if (recipient == address(0)) recipient = askOrder.signer;

        isCancelledOrClaimed[askHash] = true;
        require(
            _transferFeesAndFunds(
                askOrder.token,
                askOrder.tokenId,
                askOrder.currency,
                best.bidder,
                recipient,
                best.price * best.amount
            ),
            "SHOYU: FAILED_TO_TRANSFER_FUNDS"
        );
        amountFilled[askHash] = amountFilled[askHash] + best.amount;

        address bidRecipient = best.recipient;
        if (bidRecipient == address(0)) bidRecipient = best.bidder;
        _transfer(askOrder.token, askOrder.signer, bidRecipient, askOrder.tokenId, best.amount);

        delete bestBid[askHash];

        emit Claim(askHash, best.bidder, best.amount, best.price, bidRecipient, best.referrer);
    }

    function _validate(Orders.Ask memory askOrder, bytes32 askHash) internal view {
        require(!isCancelledOrClaimed[askHash], "SHOYU: CANCELLED_OR_CLAIMED");

        require(askOrder.signer != address(0), "SHOYU: INVALID_MAKER");
        require(askOrder.token != address(0), "SHOYU: INVALID_NFT");
        require(askOrder.amount > 0, "SHOYU: INVALID_AMOUNT");
        require(askOrder.strategy != address(0), "SHOYU: INVALID_STRATEGY");
        require(askOrder.currency != address(0), "SHOYU: INVALID_CURRENCY");
        require(ITokenFactory(factory()).isStrategyWhitelisted(askOrder.strategy), "SHOYU: STRATEGY_NOT_WHITELISTED");
    }

    function _transferFeesAndFunds(
        address token,
        uint256 tokenId,
        address currency,
        address from,
        address to,
        uint256 amount
    ) internal returns (bool) {
        if (!_safeTransferFrom(currency, from, address(this), amount)) {
            return false;
        }

        address _factory = factory();
        uint256 remainder = amount;
        {
            (address protocolFeeRecipient, uint8 protocolFeePermil) = ITokenFactory(_factory).protocolFeeInfo();
            uint256 protocolFeeAmount = (amount * protocolFeePermil) / 1000;
            IERC20(currency).safeTransfer(protocolFeeRecipient, protocolFeeAmount);
            remainder -= protocolFeeAmount;
        }

        {
            (address operationalFeeRecipient, uint8 operationalFeePermil) =
                ITokenFactory(_factory).operationalFeeInfo();
            uint256 operationalFeeAmount = (amount * operationalFeePermil) / 1000;
            IERC20(currency).safeTransfer(operationalFeeRecipient, operationalFeeAmount);
            remainder -= operationalFeeAmount;
        }

        try IERC2981(token).royaltyInfo(tokenId, amount) returns (
            address royaltyFeeRecipient,
            uint256 royaltyFeeAmount
        ) {
            if (royaltyFeeAmount > 0) {
                remainder -= royaltyFeeAmount;
                _transferRoyaltyFee(currency, royaltyFeeRecipient, royaltyFeeAmount);
            }
        } catch {}

        IERC20(currency).safeTransfer(to, remainder);
        return true;
    }

    function _safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) private returns (bool) {
        (bool success, bytes memory returndata) =
            token.call(abi.encodeWithSelector(IERC20(token).transferFrom.selector, from, to, value));
        return success && (returndata.length == 0 || abi.decode(returndata, (bool)));
    }

    function _transferRoyaltyFee(
        address currency,
        address to,
        uint256 amount
    ) internal {
        IERC20(currency).safeTransfer(to, amount);
        if (Address.isContract(to)) {
            try IDividendPayingERC20(to).sync() returns (uint256) {} catch {}
        }
    }
}// MIT

pragma solidity ^0.8.0;


interface IERC721 is IERC165 {

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function balanceOf(address owner) external view returns (uint256 balance);


    function ownerOf(uint256 tokenId) external view returns (address owner);


    function safeTransferFrom(address from, address to, uint256 tokenId) external;


    function transferFrom(address from, address to, uint256 tokenId) external;


    function approve(address to, uint256 tokenId) external;


    function getApproved(uint256 tokenId) external view returns (address operator);


    function setApprovalForAll(address operator, bool _approved) external;


    function isApprovedForAll(address owner, address operator) external view returns (bool);


    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;

}// MIT

pragma solidity ^0.8.0;


interface IERC721Metadata is IERC721 {


    function name() external view returns (string memory);


    function symbol() external view returns (string memory);


    function tokenURI(uint256 tokenId) external view returns (string memory);

}// MIT

pragma solidity >=0.5.0;

interface IOwnable {

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function owner() external view returns (address);


    function renounceOwnership() external;


    function transferOwnership(address newOwner) external;

}// MIT

pragma solidity >=0.5.0;



interface IBaseNFT721 is IERC721, IERC721Metadata, IOwnable {

    event SetTokenURI(uint256 indexed tokenId, string uri);
    event SetBaseURI(string uri);
    event ParkTokenIds(uint256 toTokenId);
    event Burn(uint256 indexed tokenId, uint256 indexed label, bytes32 data);

    function PERMIT_TYPEHASH() external view returns (bytes32);


    function PERMIT_ALL_TYPEHASH() external view returns (bytes32);


    function DOMAIN_SEPARATOR() external view returns (bytes32);


    function factory() external view returns (address);


    function nonces(uint256 tokenId) external view returns (uint256);


    function noncesForAll(address account) external view returns (uint256);


    function parked(uint256 tokenId) external view returns (bool);


    function initialize(
        string calldata name,
        string calldata symbol,
        address _owner
    ) external;


    function setTokenURI(uint256 id, string memory uri) external;


    function setBaseURI(string memory uri) external;


    function parkTokenIds(uint256 toTokenId) external;


    function mint(
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;


    function mintBatch(
        address to,
        uint256[] calldata tokenIds,
        bytes calldata data
    ) external;


    function burn(
        uint256 tokenId,
        uint256 label,
        bytes32 data
    ) external;


    function burnBatch(uint256[] calldata tokenIds) external;


    function permit(
        address spender,
        uint256 tokenId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;


    function permitAll(
        address owner,
        address spender,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

}// MIT

pragma solidity >=0.5.0;


interface INFT721 is IBaseNFT721, IBaseExchange {

    event SetRoyaltyFeeRecipient(address recipient);
    event SetRoyaltyFee(uint8 fee);

    function initialize(
        address _owner,
        string calldata _name,
        string calldata _symbol,
        uint256[] calldata tokenIds,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external;


    function initialize(
        address _owner,
        string calldata _name,
        string calldata _symbol,
        uint256 toTokenId,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external;


    function DOMAIN_SEPARATOR() external view override(IBaseNFT721, IBaseExchange) returns (bytes32);


    function factory() external view override(IBaseNFT721, IBaseExchange) returns (address);


    function setRoyaltyFeeRecipient(address _royaltyFeeRecipient) external;


    function setRoyaltyFee(uint8 _royaltyFee) external;

}// MIT

pragma solidity ^0.8.0;

library Strings {

    bytes16 private constant alphabet = "0123456789abcdef";

    function toString(uint256 value) internal pure returns (string memory) {


        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function toHexString(uint256 value) internal pure returns (string memory) {

        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {

        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = alphabet[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

}// MIT

pragma solidity ^0.8.0;


abstract contract ERC165 is IERC165 {
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}// MIT

pragma solidity ^0.8.0;

interface IERC721Receiver {

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);

}// MIT

pragma solidity =0.8.3;


contract ERC721Initializable is Initializable, ERC165, IERC721, IERC721Metadata {

    using Address for address;
    using Strings for uint256;

    string private _name;

    string private _symbol;

    uint256 private _toTokenIdParked;

    mapping(uint256 => address) private _owners;

    mapping(address => uint256) private _balances;

    mapping(uint256 => address) private _tokenApprovals;

    mapping(address => mapping(address => bool)) private _operatorApprovals;

    function __ERC721_init(string memory name_, string memory symbol_) internal initializer {

        __ERC721_init_unchained(name_, symbol_);
    }

    function __ERC721_init_unchained(string memory name_, string memory symbol_) internal initializer {

        _name = name_;
        _symbol = symbol_;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {

        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function balanceOf(address owner) public view virtual override returns (uint256) {

        require(owner != address(0), "SHOYU: INVALID_OWNER");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view virtual override returns (address) {

        return _owners[tokenId];
    }

    function name() public view virtual override returns (string memory) {

        return _name;
    }

    function symbol() public view virtual override returns (string memory) {

        return _symbol;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        require(_exists(tokenId), "SHOYU: INVALID_TOKEN_ID");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    function _baseURI() internal view virtual returns (string memory) {

        return "";
    }

    function approve(address to, uint256 tokenId) public virtual override {

        address owner = ERC721Initializable.ownerOf(tokenId);
        require(to != owner, "SHOYU: INVALID_TO");

        require(msg.sender == owner || isApprovedForAll(owner, msg.sender), "SHOYU: FORBIDDEN");

        _approve(to, tokenId);
    }

    function getApproved(uint256 tokenId) public view virtual override returns (address) {

        require(_exists(tokenId), "SHOYU: INVALID_TOKEN_ID");

        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public virtual override {

        _setApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {

        return _operatorApprovals[owner][operator];
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {

        require(_isApprovedOrOwner(msg.sender, tokenId), "SHOYU: NOT_APPROVED_NOR_OWNER");

        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {

        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {

        require(_isApprovedOrOwner(msg.sender, tokenId), "SHOYU: FORBIDDEN");
        _safeTransfer(from, to, tokenId, _data);
    }

    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {

        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "SHOYU: INVALID_RECEIVER");
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {

        return _owners[tokenId] != address(0);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {

        require(_exists(tokenId), "SHOYU: INVALID_TOKEN_ID");
        address owner = ERC721Initializable.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal {

        require(operator != owner, "SHOYU: INVALID_OPERATOR");

        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }

    function _parked(uint256 tokenId) internal view virtual returns (bool) {

        address owner = ERC721Initializable.ownerOf(tokenId);
        return owner == address(0) && tokenId < _toTokenIdParked;
    }

    function _parkTokenIds(uint256 toTokenId) internal virtual {

        uint256 fromTokenId = _toTokenIdParked;
        require(toTokenId > fromTokenId, "SHOYU: INVALID_TO_TOKEN_ID");

        _toTokenIdParked = toTokenId;
    }

    function _safeMint(address to, uint256 tokenId) internal virtual {

        _safeMint(to, tokenId, "");
    }

    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {

        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, _data), "SHOYU: INVALID_RECEIVER");
    }

    function _mint(address to, uint256 tokenId) internal virtual {

        require(to != address(0), "SHOYU: INVALID_TO");
        require(!_exists(tokenId), "SHOYU: ALREADY_MINTED");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal virtual {

        address owner = ERC721Initializable.ownerOf(tokenId);
        require(owner != address(0), "SHOYU: INVALID_TOKEN_ID");

        _beforeTokenTransfer(owner, address(0), tokenId);

        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }

    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {

        require(ERC721Initializable.ownerOf(tokenId) == from, "SHOYU: TRANSFER_FORBIDDEN");
        require(to != address(0), "SHOYU: INVALID_RECIPIENT");

        _beforeTokenTransfer(from, to, tokenId);

        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _approve(address to, uint256 tokenId) internal virtual {

        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721Initializable.ownerOf(tokenId), to, tokenId);
    }

    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {

        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver(to).onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("SHOYU: INVALID_RECEIVER");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}

}// MIT

pragma solidity =0.8.3;



abstract contract OwnableInitializable is Initializable, IOwnable {
    address private _owner;

    function __Ownable_init(address __owner) internal initializer {
        __Ownable_init_unchained(__owner);
    }

    function __Ownable_init_unchained(address __owner) internal initializer {
        _owner = __owner;
        emit OwnershipTransferred(address(0), __owner);
    }

    function owner() public view virtual override returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == msg.sender, "SHOYU: FORBIDDEN");
        _;
    }

    function renounceOwnership() public virtual override onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public virtual override onlyOwner {
        require(newOwner != address(0), "SHOYU: INVALID_NEW_OWNER");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}// MIT

pragma solidity =0.8.3;



abstract contract BaseNFT721 is ERC721Initializable, OwnableInitializable, IBaseNFT721 {
    bytes32 public constant override PERMIT_TYPEHASH =
        0x49ecf333e5b8c95c40fdafc95c1ad136e8914a8fb55e9dc8bb01eaa83a2df9ad;
    bytes32 public constant override PERMIT_ALL_TYPEHASH =
        0xdaab21af31ece73a508939fedd476a5ee5129a5ed4bb091f3236ffb45394df62;
    bytes32 internal _DOMAIN_SEPARATOR;
    uint256 internal _CACHED_CHAIN_ID;

    address internal _factory;
    string internal __baseURI;
    mapping(uint256 => string) internal _uris;

    mapping(uint256 => uint256) public override nonces;
    mapping(address => uint256) public override noncesForAll;

    function initialize(
        string memory _name,
        string memory _symbol,
        address _owner
    ) public override initializer {
        __ERC721_init(_name, _symbol);
        __Ownable_init(_owner);
        _factory = msg.sender;

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view virtual override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function factory() public view virtual override returns (address) {
        return _factory;
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721Initializable, IERC721Metadata)
        returns (string memory)
    {
        require(_exists(tokenId) || _parked(tokenId), "SHOYU: INVALID_TOKEN_ID");

        string memory _uri = _uris[tokenId];
        if (bytes(_uri).length > 0) {
            return _uri;
        } else {
            string memory baseURI = __baseURI;
            if (bytes(baseURI).length > 0) {
                return string(abi.encodePacked(baseURI, Strings.toString(tokenId), ".json"));
            } else {
                baseURI = ITokenFactory(_factory).baseURI721();
                string memory addy = Strings.toHexString(uint160(address(this)), 20);
                return string(abi.encodePacked(baseURI, addy, "/", Strings.toString(tokenId), ".json"));
            }
        }
    }

    function parked(uint256 tokenId) external view override returns (bool) {
        return _parked(tokenId);
    }

    function setTokenURI(uint256 id, string memory newURI) external override onlyOwner {
        _uris[id] = newURI;

        emit SetTokenURI(id, newURI);
    }

    function setBaseURI(string memory uri) external override onlyOwner {
        __baseURI = uri;

        emit SetBaseURI(uri);
    }

    function parkTokenIds(uint256 toTokenId) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        _parkTokenIds(toTokenId);

        emit ParkTokenIds(toTokenId);
    }

    function mint(
        address to,
        uint256 tokenId,
        bytes memory data
    ) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        _safeMint(to, tokenId, data);
    }

    function mintBatch(
        address to,
        uint256[] memory tokenIds,
        bytes memory data
    ) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        for (uint256 i = 0; i < tokenIds.length; i++) {
            _safeMint(to, tokenIds[i], data);
        }
    }

    function burn(
        uint256 tokenId,
        uint256 label,
        bytes32 data
    ) external override {
        require(ownerOf(tokenId) == msg.sender, "SHOYU: FORBIDDEN");

        _burn(tokenId);

        emit Burn(tokenId, label, data);
    }

    function burnBatch(uint256[] memory tokenIds) external override {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            require(ownerOf(tokenId) == msg.sender, "SHOYU: FORBIDDEN");

            _burn(tokenId);
        }
    }

    function permit(
        address spender,
        uint256 tokenId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(block.timestamp <= deadline, "SHOYU: EXPIRED");

        address owner = ownerOf(tokenId);
        require(owner != address(0), "SHOYU: INVALID_TOKENID");
        require(spender != owner, "SHOYU: NOT_NECESSARY");

        bytes32 hash = keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, nonces[tokenId]++, deadline));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());

        _approve(spender, tokenId);
    }

    function permitAll(
        address owner,
        address spender,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(block.timestamp <= deadline, "SHOYU: EXPIRED");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");
        require(spender != owner, "SHOYU: NOT_NECESSARY");

        bytes32 hash = keccak256(abi.encode(PERMIT_ALL_TYPEHASH, owner, spender, noncesForAll[owner]++, deadline));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());

        _setApprovalForAll(owner, spender, true);
    }
}// MIT

pragma solidity =0.8.3;


contract NFT721V0 is BaseNFT721, BaseExchange, IERC2981, INFT721 {
    uint8 internal _MAX_ROYALTY_FEE;

    address internal _royaltyFeeRecipient;
    uint8 internal _royaltyFee; // out of 1000

    function initialize(
        address _owner,
        string memory _name,
        string memory _symbol,
        uint256[] memory tokenIds,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override initializer {
        __BaseNFTExchange_init();
        initialize(_name, _symbol, _owner);
        _MAX_ROYALTY_FEE = ITokenFactory(_factory).MAX_ROYALTY_FEE();

        for (uint256 i = 0; i < tokenIds.length; i++) {
            _safeMint(_owner, tokenIds[i]);
        }

        _setRoyaltyFeeRecipient(royaltyFeeRecipient);
        _royaltyFee = type(uint8).max;
        if (royaltyFee != 0) _setRoyaltyFee(royaltyFee);
    }

    function initialize(
        address _owner,
        string memory _name,
        string memory _symbol,
        uint256 toTokenId,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override initializer {
        __BaseNFTExchange_init();
        initialize(_name, _symbol, _owner);
        _MAX_ROYALTY_FEE = ITokenFactory(_factory).MAX_ROYALTY_FEE();

        _parkTokenIds(toTokenId);

        emit ParkTokenIds(toTokenId);

        _setRoyaltyFeeRecipient(royaltyFeeRecipient);
        _royaltyFee = type(uint8).max;
        if (royaltyFee != 0) _setRoyaltyFee(royaltyFee);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721Initializable, IERC165)
        returns (bool)
    {
        return interfaceId == 0x2a55205a || super.supportsInterface(interfaceId);
    }

    function DOMAIN_SEPARATOR() public view override(BaseNFT721, BaseExchange, INFT721) returns (bytes32) {
        return BaseNFT721.DOMAIN_SEPARATOR();
    }

    function factory() public view override(BaseNFT721, BaseExchange, INFT721) returns (address) {
        return _factory;
    }

    function royaltyInfo(uint256, uint256 _salePrice) external view override returns (address, uint256) {
        uint256 royaltyAmount;
        if (_royaltyFee != type(uint8).max) royaltyAmount = (_salePrice * _royaltyFee) / 1000;
        return (_royaltyFeeRecipient, royaltyAmount);
    }

    function _transfer(
        address,
        address from,
        address to,
        uint256 tokenId,
        uint256
    ) internal override {
        if (from == owner() && _parked(tokenId)) {
            _safeMint(to, tokenId);
        } else {
            _transfer(from, to, tokenId);
        }
    }

    function setRoyaltyFeeRecipient(address royaltyFeeRecipient) public override onlyOwner {
        _setRoyaltyFeeRecipient(royaltyFeeRecipient);
    }

    function setRoyaltyFee(uint8 royaltyFee) public override onlyOwner {
        _setRoyaltyFee(royaltyFee);
    }

    function _setRoyaltyFeeRecipient(address royaltyFeeRecipient) internal {
        require(royaltyFeeRecipient != address(0), "SHOYU: INVALID_FEE_RECIPIENT");

        _royaltyFeeRecipient = royaltyFeeRecipient;

        emit SetRoyaltyFeeRecipient(royaltyFeeRecipient);
    }

    function _setRoyaltyFee(uint8 royaltyFee) internal {
        if (_royaltyFee == type(uint8).max) {
            require(royaltyFee <= _MAX_ROYALTY_FEE, "SHOYU: INVALID_FEE");
        } else {
            require(royaltyFee < _royaltyFee, "SHOYU: INVALID_FEE");
        }

        _royaltyFee = royaltyFee;

        emit SetRoyaltyFee(royaltyFee);
    }
}// MIT

pragma solidity ^0.8.0;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}// MIT

pragma solidity ^0.8.0;

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}// MIT

pragma solidity ^0.8.0;


interface IERC1155 is IERC165 {
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);

    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    event URI(string value, uint256 indexed id);

    function balanceOf(address account, uint256 id) external view returns (uint256);

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) external view returns (uint256[] memory);

    function setApprovalForAll(address operator, bool approved) external;

    function isApprovedForAll(address account, address operator) external view returns (bool);

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;

    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external;
}// MIT

pragma solidity ^0.8.0;


interface IERC1155MetadataURI is IERC1155 {
    function uri(uint256 id) external view returns (string memory);
}// MIT

pragma solidity >=0.5.0;



interface IBaseNFT1155 is IERC1155, IERC1155MetadataURI, IOwnable {
    event SetURI(uint256 indexed id, string uri);
    event SetBaseURI(string uri);
    event Burn(uint256 indexed tokenId, uint256 amount, uint256 indexed label, bytes32 data);

    function PERMIT_TYPEHASH() external view returns (bytes32);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function factory() external view returns (address);

    function nonces(address account) external view returns (uint256);

    function initialize(address _owner) external;

    function setURI(uint256 id, string memory uri) external;

    function setBaseURI(string memory baseURI) external;

    function mint(
        address to,
        uint256 tokenId,
        uint256 amount,
        bytes calldata data
    ) external;

    function mintBatch(
        address to,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;

    function burn(
        uint256 tokenId,
        uint256 amount,
        uint256 label,
        bytes32 data
    ) external;

    function burnBatch(uint256[] calldata tokenIds, uint256[] calldata amounts) external;

    function permit(
        address owner,
        address spender,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}// MIT

pragma solidity >=0.5.0;


interface ISocialToken is IDividendPayingERC20, IOwnable {
    event Burn(uint256 amount, uint256 indexed label, bytes32 data);

    function initialize(
        address owner,
        string memory name,
        string memory symbol,
        address dividendToken,
        uint256 initialSupply
    ) external;

    function PERMIT_TYPEHASH() external view returns (bytes32);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function factory() external view returns (address);

    function nonces(address owner) external view returns (uint256);

    function mint(address account, uint256 value) external;

    function burn(
        uint256 value,
        uint256 id,
        bytes32 data
    ) external;

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}// MIT

pragma solidity =0.8.3;

contract ProxyFactory {
    function _createProxy(address target, bytes memory initData) internal returns (address proxy) {
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            proxy := create(0, clone, 0x37)
        }

        if (initData.length > 0) {
            (bool success, ) = proxy.call(initData);
            require(success, "SHOYU: CALL_FAILURE");
        }
    }

    function _isProxy(address target, address query) internal view returns (bool result) {
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x363d3d373d3d3d363d7300000000000000000000000000000000000000000000)
            mstore(add(clone, 0xa), targetBytes)
            mstore(add(clone, 0x1e), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)

            let other := add(clone, 0x40)
            extcodecopy(query, other, 0, 0x2d)
            result := and(eq(mload(clone), mload(other)), eq(mload(add(clone, 0xd)), mload(add(other, 0xd))))
        }
    }
}// MIT

pragma solidity =0.8.3;



contract TokenFactory is ProxyFactory, Ownable, ITokenFactory {
    uint8 public constant override MAX_ROYALTY_FEE = 250; // 25%
    uint8 public constant override MAX_OPERATIONAL_FEE = 50; // 5%
    bytes32 public constant override PARK_TOKEN_IDS_721_TYPEHASH =
        0x3fddacac0a7d8b05f741f01ff6becadd9986be8631a2af41a675f365dd74090d;
    bytes32 public constant override MINT_BATCH_721_TYPEHASH =
        0x884adba7f4e17962aed36c871036adea39c6d9f81fb25407a78db239e9731e86;
    bytes32 public constant override MINT_BATCH_1155_TYPEHASH =
        0xb47ce0f6456fcc2f16b7d6e7b0255eb73822b401248e672a4543c2b3d7183043;
    bytes32 public constant override MINT_SOCIAL_TOKEN_TYPEHASH =
        0x8f4bf92e5271f5ec2f59dc3fc74368af0064fb84b40a3de9150dd26c08cda104;
    bytes32 internal immutable _DOMAIN_SEPARATOR;
    uint256 internal immutable _CACHED_CHAIN_ID;

    address[] internal _targets721;
    address[] internal _targets1155;
    address[] internal _targetsSocialToken;

    address internal _protocolFeeRecipient;
    uint8 internal _protocolFee; // out of 1000
    address internal _operationalFeeRecipient;
    uint8 internal _operationalFee; // out of 1000

    mapping(address => uint256) public override nonces;

    string public override baseURI721;
    string public override baseURI1155;

    address public override erc721Exchange;
    address public override erc1155Exchange;
    mapping(address => bool) public override isDeployerWhitelisted;
    mapping(address => bool) public override isStrategyWhitelisted;

    modifier onlyDeployer {
        require(isDeployerWhitelisted[address(0)] || isDeployerWhitelisted[msg.sender], "SHOYU: FORBIDDEN");
        _;
    }

    constructor(
        address protocolFeeRecipient,
        uint8 protocolFee,
        address operationalFeeRecipient,
        uint8 operationalFee,
        string memory _baseURI721,
        string memory _baseURI1155
    ) {
        _protocolFeeRecipient = protocolFeeRecipient;
        _protocolFee = protocolFee;
        _operationalFeeRecipient = operationalFeeRecipient;
        _operationalFee = operationalFee;

        baseURI721 = _baseURI721;
        baseURI1155 = _baseURI1155;

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function protocolFeeInfo() external view override returns (address recipient, uint8 permil) {
        return (_protocolFeeRecipient, _protocolFee);
    }

    function operationalFeeInfo() external view override returns (address recipient, uint8 permil) {
        return (_operationalFeeRecipient, _operationalFee);
    }

    function setBaseURI721(string memory uri) external override onlyOwner {
        baseURI721 = uri;

        emit SetBaseURI721(uri);
    }

    function setBaseURI1155(string memory uri) external override onlyOwner {
        baseURI1155 = uri;

        emit SetBaseURI1155(uri);
    }

    function setProtocolFeeRecipient(address protocolFeeRecipient) external override onlyOwner {
        require(protocolFeeRecipient != address(0), "SHOYU: INVALID_FEE_RECIPIENT");

        _protocolFeeRecipient = protocolFeeRecipient;

        emit SetProtocolFeeRecipient(protocolFeeRecipient);
    }

    function setOperationalFeeRecipient(address operationalFeeRecipient) external override onlyOwner {
        require(operationalFeeRecipient != address(0), "SHOYU: INVALID_RECIPIENT");

        _operationalFeeRecipient = operationalFeeRecipient;

        emit SetOperationalFeeRecipient(operationalFeeRecipient);
    }

    function setOperationalFee(uint8 operationalFee) external override onlyOwner {
        require(operationalFee <= MAX_OPERATIONAL_FEE, "SHOYU: INVALID_FEE");

        _operationalFee = operationalFee;

        emit SetOperationalFee(operationalFee);
    }

    function setDeployerWhitelisted(address deployer, bool whitelisted) external override onlyOwner {
        isDeployerWhitelisted[deployer] = whitelisted;

        emit SetDeployerWhitelisted(deployer, whitelisted);
    }

    function setStrategyWhitelisted(address strategy, bool whitelisted) external override onlyOwner {
        require(strategy != address(0), "SHOYU: INVALID_ADDRESS");

        isStrategyWhitelisted[strategy] = whitelisted;

        emit SetStrategyWhitelisted(strategy, whitelisted);
    }

    function upgradeNFT721(address newTarget) external override onlyOwner {
        _targets721.push(newTarget);

        emit UpgradeNFT721(newTarget);
    }

    function upgradeNFT1155(address newTarget) external override onlyOwner {
        _targets1155.push(newTarget);

        emit UpgradeNFT1155(newTarget);
    }

    function upgradeSocialToken(address newTarget) external override onlyOwner {
        _targetsSocialToken.push(newTarget);

        emit UpgradeSocialToken(newTarget);
    }

    function upgradeERC721Exchange(address exchange) external override onlyOwner {
        erc721Exchange = exchange;

        emit UpgradeERC721Exchange(exchange);
    }

    function upgradeERC1155Exchange(address exchange) external override onlyOwner {
        erc1155Exchange = exchange;

        emit UpgradeERC1155Exchange(exchange);
    }

    function deployNFT721AndMintBatch(
        address owner,
        string calldata name,
        string calldata symbol,
        uint256[] memory tokenIds,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override onlyDeployer returns (address nft) {
        require(bytes(name).length > 0, "SHOYU: INVALID_NAME");
        require(bytes(symbol).length > 0, "SHOYU: INVALID_SYMBOL");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");

        nft = _createProxy(
            _targets721[_targets721.length - 1],
            abi.encodeWithSignature(
                "initialize(address,string,string,uint256[],address,uint8)",
                owner,
                name,
                symbol,
                tokenIds,
                royaltyFeeRecipient,
                royaltyFee
            )
        );

        emit DeployNFT721AndMintBatch(nft, owner, name, symbol, tokenIds, royaltyFeeRecipient, royaltyFee);
    }

    function deployNFT721AndPark(
        address owner,
        string calldata name,
        string calldata symbol,
        uint256 toTokenId,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override onlyDeployer returns (address nft) {
        require(bytes(name).length > 0, "SHOYU: INVALID_NAME");
        require(bytes(symbol).length > 0, "SHOYU: INVALID_SYMBOL");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");

        nft = _createProxy(
            _targets721[_targets721.length - 1],
            abi.encodeWithSignature(
                "initialize(address,string,string,uint256,address,uint8)",
                owner,
                name,
                symbol,
                toTokenId,
                royaltyFeeRecipient,
                royaltyFee
            )
        );

        emit DeployNFT721AndPark(nft, owner, name, symbol, toTokenId, royaltyFeeRecipient, royaltyFee);
    }

    function isNFT721(address query) external view override returns (bool result) {
        if (query == address(0)) return false;
        for (uint256 i = _targets721.length; i >= 1; i--) {
            if (_isProxy(_targets721[i - 1], query)) {
                return true;
            }
        }
        return false;
    }

    function deployNFT1155AndMintBatch(
        address owner,
        uint256[] memory tokenIds,
        uint256[] memory amounts,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override onlyDeployer returns (address nft) {
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");
        require(tokenIds.length == amounts.length, "SHOYU: LENGTHS_NOT_EQUAL");
        nft = _createProxy(
            _targets1155[_targets1155.length - 1],
            abi.encodeWithSignature(
                "initialize(address,uint256[],uint256[],address,uint8)",
                owner,
                tokenIds,
                amounts,
                royaltyFeeRecipient,
                royaltyFee
            )
        );

        emit DeployNFT1155AndMintBatch(nft, owner, tokenIds, amounts, royaltyFeeRecipient, royaltyFee);
    }

    function isNFT1155(address query) external view override returns (bool result) {
        if (query == address(0)) return false;
        for (uint256 i = _targets1155.length; i >= 1; i--) {
            if (_isProxy(_targets1155[i - 1], query)) {
                return true;
            }
        }
        return false;
    }

    function deploySocialToken(
        address owner,
        string memory name,
        string memory symbol,
        address dividendToken,
        uint256 initialSupply
    ) external override onlyDeployer returns (address proxy) {
        require(bytes(name).length > 0, "SHOYU: INVALID_NAME");
        require(bytes(symbol).length > 0, "SHOYU: INVALID_SYMBOL");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");

        bytes memory initData =
            abi.encodeWithSignature(
                "initialize(address,string,string,address,uint256)",
                owner,
                name,
                symbol,
                dividendToken,
                initialSupply
            );
        proxy = _createProxy(_targetsSocialToken[_targetsSocialToken.length - 1], initData);

        emit DeploySocialToken(proxy, owner, name, symbol, dividendToken, initialSupply);
    }

    function isSocialToken(address query) external view override returns (bool result) {
        if (query == address(0)) return false;
        for (uint256 i = _targetsSocialToken.length; i >= 1; i--) {
            if (_isProxy(_targetsSocialToken[i - 1], query)) {
                return true;
            }
        }
        return false;
    }

    function parkTokenIds721(
        address nft,
        uint256 toTokenId,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        address owner = IBaseNFT721(nft).owner();
        bytes32 hash = keccak256(abi.encode(PARK_TOKEN_IDS_721_TYPEHASH, nft, toTokenId, nonces[owner]++));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());
        IBaseNFT721(nft).parkTokenIds(toTokenId);
    }

    function mintBatch721(
        address nft,
        address to,
        uint256[] calldata tokenIds,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        address owner = IBaseNFT721(nft).owner();
        bytes32 hash = keccak256(abi.encode(MINT_BATCH_721_TYPEHASH, nft, to, tokenIds, data, nonces[owner]++));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());
        IBaseNFT721(nft).mintBatch(to, tokenIds, data);
    }

    function mintBatch1155(
        address nft,
        address to,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        address owner = IBaseNFT1155(nft).owner();
        bytes32 hash =
            keccak256(abi.encode(MINT_BATCH_1155_TYPEHASH, nft, to, tokenIds, amounts, data, nonces[owner]++));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());
        IBaseNFT1155(nft).mintBatch(to, tokenIds, amounts, data);
    }

    function mintSocialToken(
        address token,
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        address owner = ISocialToken(token).owner();
        bytes32 hash = keccak256(abi.encode(MINT_SOCIAL_TOKEN_TYPEHASH, token, to, amount, nonces[owner]++));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());
        ISocialToken(token).mint(to, amount);
    }
}// MIT

pragma solidity >=0.5.0;

interface IPaymentSplitterFactory {
    event DeployPaymentSplitter(
        address indexed owner,
        string title,
        address[] payees,
        uint256[] shares,
        address splitter
    );

    function deployPaymentSplitter(
        address owner,
        string calldata title,
        address[] calldata payees,
        uint256[] calldata shares
    ) external returns (address splitter);

    function isPaymentSplitter(address query) external view returns (bool result);
}// MIT

pragma solidity >=0.5.0;

interface IPaymentSplitter {
    event PayeeAdded(address account, uint256 shares);
    event PaymentReleased(address token, address to, uint256 amount);

    function initialize(
        string calldata _title,
        address[] calldata _payees,
        uint256[] calldata _shares
    ) external;

    function title() external view returns (string memory);

    function totalShares() external view returns (uint256);

    function totalReleased(address account) external view returns (uint256);

    function shares(address account) external view returns (uint256);

    function released(address token, address account) external view returns (uint256);

    function payees(uint256 index) external view returns (address);

    function release(address token, address account) external;
}// MIT

pragma solidity =0.8.3;


library TokenHelper {
    using SafeERC20 for IERC20;

    address public constant ETH = 0x0000000000000000000000000000000000000000;

    function balanceOf(address token, address account) internal view returns (uint256) {
        if (token == ETH) {
            return account.balance;
        } else {
            return IERC20(token).balanceOf(account);
        }
    }

    function safeTransfer(
        address token,
        address to,
        uint256 amount
    ) internal {
        if (token == ETH) {
            (bool success, ) = to.call{value: amount}("");
            require(success, "SHOYU: TRANSFER_FAILURE");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }
}// MIT

pragma solidity =0.8.3;



contract PaymentSplitter is Initializable, IPaymentSplitter {
    using TokenHelper for address;

    string public override title;

    uint256 public override totalShares;
    mapping(address => uint256) public override totalReleased;

    mapping(address => uint256) public override shares;
    mapping(address => mapping(address => uint256)) public override released;
    address[] public override payees;

    function initialize(
        string calldata _title,
        address[] calldata _payees,
        uint256[] calldata _shares
    ) external override initializer {
        require(_payees.length == _shares.length, "SHOYU: LENGTHS_NOT_EQUAL");
        require(_payees.length > 0, "SHOYU: LENGTH_TOO_SHORT");

        title = _title;

        for (uint256 i = 0; i < _payees.length; i++) {
            _addPayee(_payees[i], _shares[i]);
        }
    }

    function release(address token, address account) external virtual override {
        require(shares[account] > 0, "SHOYU: FORBIDDEN");

        uint256 totalReceived = token.balanceOf(address(this)) + totalReleased[token];
        uint256 payment = (totalReceived * shares[account]) / totalShares - released[token][account];

        require(payment != 0, "SHOYU: NO_PAYMENT");

        released[token][account] += payment;
        totalReleased[token] += payment;

        token.safeTransfer(account, payment);
        emit PaymentReleased(token, account, payment);
    }

    function _addPayee(address account, uint256 _shares) private {
        require(account != address(0), "SHOYU: INVALID_ADDRESS");
        require(_shares > 0, "SHOYU: INVALID_SHARES");
        require(shares[account] == 0, "SHOYU: ALREADY_ADDED");

        payees.push(account);
        shares[account] = _shares;
        totalShares = totalShares + _shares;
        emit PayeeAdded(account, _shares);
    }
}// MIT

pragma solidity =0.8.3;


contract PaymentSplitterFactory is ProxyFactory, IPaymentSplitterFactory {
    address internal _target;

    constructor() {
        PaymentSplitter target = new PaymentSplitter();
        address[] memory payees = new address[](1);
        payees[0] = msg.sender;
        uint256[] memory shares = new uint256[](1);
        shares[0] = 1;
        target.initialize("", payees, shares);
        _target = address(target);
    }

    function deployPaymentSplitter(
        address owner,
        string calldata title,
        address[] calldata payees,
        uint256[] calldata shares
    ) external override returns (address splitter) {
        splitter = _createProxy(
            _target,
            abi.encodeWithSignature("initialize(string,address[],uint256[])", title, payees, shares)
        );

        emit DeployPaymentSplitter(owner, title, payees, shares, splitter);
    }

    function isPaymentSplitter(address query) external view override returns (bool result) {
        return _isProxy(_target, query);
    }
}// MIT

pragma solidity ^0.8.0;


contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    string private _name;

    string private _symbol;

    mapping (uint256 => address) private _owners;

    mapping (address => uint256) private _balances;

    mapping (uint256 => address) private _tokenApprovals;

    mapping (address => mapping (address => bool)) private _operatorApprovals;

    constructor (string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC721).interfaceId
            || interfaceId == type(IERC721Metadata).interfaceId
            || super.supportsInterface(interfaceId);
    }

    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0
            ? string(abi.encodePacked(baseURI, tokenId.toString()))
            : '';
    }

    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory _data) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal virtual {
        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
        private returns (bool)
    {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver(to).onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual { }
}// MIT

pragma solidity =0.8.3;


contract ERC721RoyaltyMock is ERC721("Mock", "MOCK") {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function safeMint(
        address to,
        uint256 tokenId,
        bytes memory data
    ) external {
        _safeMint(to, tokenId, data);
    }

    function safeMintBatch0(
        address[] calldata to,
        uint256[] calldata tokenId,
        bytes memory data
    ) external {
        require(to.length == tokenId.length);
        for (uint256 i = 0; i < to.length; i++) {
            _safeMint(to[i], tokenId[i], data);
        }
    }

    function safeMintBatch1(
        address to,
        uint256[] calldata tokenId,
        bytes memory data
    ) external {
        for (uint256 i = 0; i < tokenId.length; i++) {
            _safeMint(to, tokenId[i], data);
        }
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == 0x2a55205a || super.supportsInterface(interfaceId);
    }

    function royaltyInfo(uint256 _tokenId, uint256 _salePrice) external view returns (address, uint256) {
        uint256 fee = 100;
        if (_tokenId < 10) fee = 10;
        return (owner, (_salePrice * fee) / 1000);
    }
}// MIT

pragma solidity >=0.5.0;


interface INFT1155 is IBaseNFT1155, IBaseExchange {
    event SetRoyaltyFeeRecipient(address recipient);
    event SetRoyaltyFee(uint8 fee);

    function initialize(
        address _owner,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external;

    function DOMAIN_SEPARATOR() external view override(IBaseNFT1155, IBaseExchange) returns (bytes32);

    function factory() external view override(IBaseNFT1155, IBaseExchange) returns (address);

    function setRoyaltyFeeRecipient(address _royaltyFeeRecipient) external;

    function setRoyaltyFee(uint8 _royaltyFee) external;
}// MIT

pragma solidity ^0.8.0;


interface IERC1155Receiver is IERC165 {

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external
        returns(bytes4);

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external
        returns(bytes4);
}// MIT

pragma solidity =0.8.3;


contract ERC1155Initializable is Initializable, ERC165, IERC1155, IERC1155MetadataURI {
    using Address for address;

    mapping(uint256 => mapping(address => uint256)) private _balances;

    mapping(address => mapping(address => bool)) private _operatorApprovals;

    string private _uri;

    function __ERC1155_init(string memory uri_) internal initializer {
        __ERC1155_init_unchained(uri_);
    }

    function __ERC1155_init_unchained(string memory uri_) internal initializer {
        _setURI(uri_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC1155).interfaceId ||
            interfaceId == type(IERC1155MetadataURI).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function uri(uint256) public view virtual override returns (string memory) {
        return _uri;
    }

    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(account != address(0), "SHOYU: INVALID_ADDRESS");
        return _balances[id][account];
    }

    function balanceOfBatch(address[] memory accounts, uint256[] memory ids)
        public
        view
        virtual
        override
        returns (uint256[] memory)
    {
        require(accounts.length == ids.length, "SHOYU: LENGTHS_NOT_EQUAL");

        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; ++i) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    function setApprovalForAll(address operator, bool approved) public virtual override {
        _setApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[account][operator];
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public virtual override {
        require(to != address(0), "SHOYU: INVALID_ADDRESS");
        require(from == msg.sender || isApprovedForAll(from, msg.sender), "SHOYU: FORBIDDEN");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, from, to, _asSingletonArray(id), _asSingletonArray(amount), data);

        _transfer(from, to, id, amount);
        emit TransferSingle(operator, from, to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);
    }

    function _transfer(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal {
        uint256 fromBalance = _balances[id][from];
        require(fromBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
        _balances[id][from] = fromBalance - amount;
        _balances[id][to] += amount;
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public virtual override {
        require(ids.length == amounts.length, "SHOYU: LENGTHS_NOT_EQUAL");
        require(to != address(0), "SHOYU: INVALID_ADDRESS");
        require(from == msg.sender || isApprovedForAll(from, msg.sender), "SHOYU: FORBIDDEN");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, from, to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(fromBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
            _balances[id][from] = fromBalance - amount;
            _balances[id][to] += amount;
        }

        emit TransferBatch(operator, from, to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);
    }

    function _setURI(string memory newuri) internal virtual {
        _uri = newuri;
    }

    function _setApprovalForAll(
        address account,
        address operator,
        bool approved
    ) internal {
        require(account != operator, "SHOYU: NOT_ALLOWED");

        _operatorApprovals[account][operator] = approved;
        emit ApprovalForAll(account, operator, approved);
    }

    function _mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual {
        require(account != address(0), "SHOYU: INVALID_ADDRESS");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, address(0), account, _asSingletonArray(id), _asSingletonArray(amount), data);

        _balances[id][account] += amount;
        emit TransferSingle(operator, address(0), account, id, amount);

        _doSafeTransferAcceptanceCheck(operator, address(0), account, id, amount, data);
    }

    function _mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        require(to != address(0), "SHOYU: INVALID_ADDRESS");
        require(ids.length == amounts.length, "SHOYU: LENGTHS_NOT_EQUAL");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }

        emit TransferBatch(operator, address(0), to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, data);
    }

    function _burn(
        address account,
        uint256 id,
        uint256 amount
    ) internal virtual {
        require(account != address(0), "SHOYU: INVALID_ADDRESS");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, account, address(0), _asSingletonArray(id), _asSingletonArray(amount), "");

        uint256 accountBalance = _balances[id][account];
        require(accountBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
        _balances[id][account] = accountBalance - amount;

        emit TransferSingle(operator, account, address(0), id, amount);
    }

    function _burnBatch(
        address account,
        uint256[] memory ids,
        uint256[] memory amounts
    ) internal virtual {
        require(account != address(0), "SHOYU: INVALID_ADDRESS");
        require(ids.length == amounts.length, "SHOYU: LENGTHS_NOT_EQUAL");

        address operator = msg.sender;

        _beforeTokenTransfer(operator, account, address(0), ids, amounts, "");

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 accountBalance = _balances[id][account];
            require(accountBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
            _balances[id][account] = accountBalance - amount;
        }

        emit TransferBatch(operator, account, address(0), ids, amounts);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {}

    function _doSafeTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) private {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
                if (response != IERC1155Receiver(to).onERC1155Received.selector) {
                    revert("SHOYU: INVALID_RECEIVER");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("SHOYU: NO_RECEIVER");
            }
        }
    }

    function _doSafeBatchTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) private {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (
                bytes4 response
            ) {
                if (response != IERC1155Receiver(to).onERC1155BatchReceived.selector) {
                    revert("SHOYU: INVALID_RECEIVER");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("SHOYU: NO_RECEIVER");
            }
        }
    }

    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {
        uint256[] memory array = new uint256[](1);
        array[0] = element;

        return array;
    }
}// MIT

pragma solidity =0.8.3;



abstract contract BaseNFT1155 is ERC1155Initializable, OwnableInitializable, IBaseNFT1155 {
    using Strings for uint256;

    bytes32 public constant override PERMIT_TYPEHASH =
        0xdaab21af31ece73a508939fedd476a5ee5129a5ed4bb091f3236ffb45394df62;
    bytes32 internal _DOMAIN_SEPARATOR;
    uint256 internal _CACHED_CHAIN_ID;
    uint8 internal MAX_ROYALTY_FEE;

    address internal _factory;
    string internal _baseURI;
    mapping(uint256 => string) internal _uris;

    mapping(address => uint256) public override nonces;

    function initialize(address _owner) public override initializer {
        __ERC1155_init("");
        __Ownable_init(_owner);
        _factory = msg.sender;

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view virtual override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function factory() public view virtual override returns (address) {
        return _factory;
    }

    function uri(uint256 id)
        public
        view
        virtual
        override(ERC1155Initializable, IERC1155MetadataURI)
        returns (string memory)
    {
        string memory _uri = _uris[id];
        if (bytes(_uri).length > 0) {
            return _uri;
        } else {
            string memory baseURI = _baseURI;
            if (bytes(baseURI).length > 0) {
                return string(abi.encodePacked(baseURI, "{id}.json"));
            } else {
                baseURI = ITokenFactory(_factory).baseURI1155();
                string memory addy = Strings.toHexString(uint160(address(this)), 20);
                return string(abi.encodePacked(baseURI, addy, "/{id}.json"));
            }
        }
    }

    function setURI(uint256 id, string memory newURI) external override onlyOwner {
        _uris[id] = newURI;

        emit SetURI(id, newURI);
    }

    function setBaseURI(string memory baseURI) external override onlyOwner {
        _baseURI = baseURI;

        emit SetBaseURI(baseURI);
    }

    function mint(
        address to,
        uint256 tokenId,
        uint256 amount,
        bytes memory data
    ) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        _mint(to, tokenId, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] memory tokenIds,
        uint256[] memory amounts,
        bytes memory data
    ) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        _mintBatch(to, tokenIds, amounts, data);
    }

    function burn(
        uint256 tokenId,
        uint256 amount,
        uint256 label,
        bytes32 data
    ) external override {
        _burn(msg.sender, tokenId, amount);

        emit Burn(tokenId, amount, label, data);
    }

    function burnBatch(uint256[] calldata tokenIds, uint256[] calldata amounts) external override {
        _burnBatch(msg.sender, tokenIds, amounts);
    }

    function permit(
        address owner,
        address spender,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(block.timestamp <= deadline, "SHOYU: EXPIRED");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");
        require(spender != owner, "SHOYU: NOT_NECESSARY");

        bytes32 hash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, nonces[owner]++, deadline));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());

        _setApprovalForAll(owner, spender, true);
    }
}// MIT

pragma solidity =0.8.3;


contract NFT1155V0 is BaseNFT1155, BaseExchange, IERC2981, INFT1155 {
    uint8 internal _MAX_ROYALTY_FEE;

    address internal _royaltyFeeRecipient;
    uint8 internal _royaltyFee; // out of 1000

    function initialize(
        address _owner,
        uint256[] memory tokenIds,
        uint256[] memory amounts,
        address royaltyFeeRecipient,
        uint8 royaltyFee
    ) external override initializer {
        __BaseNFTExchange_init();
        initialize(_owner);
        _MAX_ROYALTY_FEE = ITokenFactory(_factory).MAX_ROYALTY_FEE();

        if (tokenIds.length > 0) {
            _mintBatch(_owner, tokenIds, amounts, "");
        }

        _setRoyaltyFeeRecipient(royaltyFeeRecipient);
        _royaltyFee = type(uint8).max;
        if (royaltyFee != 0) _setRoyaltyFee(royaltyFee);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155Initializable, IERC165)
        returns (bool)
    {
        return interfaceId == 0x2a55205a || super.supportsInterface(interfaceId);
    }

    function DOMAIN_SEPARATOR() public view override(BaseNFT1155, BaseExchange, INFT1155) returns (bytes32) {
        return BaseNFT1155.DOMAIN_SEPARATOR();
    }

    function factory() public view override(BaseNFT1155, BaseExchange, INFT1155) returns (address) {
        return _factory;
    }

    function royaltyInfo(uint256, uint256 _salePrice) external view override returns (address, uint256) {
        uint256 royaltyAmount;
        if (_royaltyFee != type(uint8).max) royaltyAmount = (_salePrice * _royaltyFee) / 1000;
        return (_royaltyFeeRecipient, royaltyAmount);
    }

    function _transfer(
        address,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) internal override {
        _transfer(from, to, tokenId, amount);
        emit TransferSingle(msg.sender, from, to, tokenId, amount);
    }

    function setRoyaltyFeeRecipient(address royaltyFeeRecipient) public override onlyOwner {
        _setRoyaltyFeeRecipient(royaltyFeeRecipient);
    }

    function setRoyaltyFee(uint8 royaltyFee) public override onlyOwner {
        _setRoyaltyFee(royaltyFee);
    }

    function _setRoyaltyFeeRecipient(address royaltyFeeRecipient) internal {
        require(royaltyFeeRecipient != address(0), "SHOYU: INVALID_FEE_RECIPIENT");

        _royaltyFeeRecipient = royaltyFeeRecipient;

        emit SetRoyaltyFeeRecipient(royaltyFeeRecipient);
    }

    function _setRoyaltyFee(uint8 royaltyFee) internal {
        if (_royaltyFee == type(uint8).max) {
            require(royaltyFee <= _MAX_ROYALTY_FEE, "SHOYU: INVALID_FEE");
        } else {
            require(royaltyFee < _royaltyFee, "SHOYU: INVALID_FEE");
        }

        _royaltyFee = royaltyFee;

        emit SetRoyaltyFee(royaltyFee);
    }
}// MIT

pragma solidity ^0.8.0;

library SafeCast {
    function toUint128(uint256 value) internal pure returns (uint128) {
        require(value < 2**128, "SafeCast: value doesn\'t fit in 128 bits");
        return uint128(value);
    }

    function toUint64(uint256 value) internal pure returns (uint64) {
        require(value < 2**64, "SafeCast: value doesn\'t fit in 64 bits");
        return uint64(value);
    }

    function toUint32(uint256 value) internal pure returns (uint32) {
        require(value < 2**32, "SafeCast: value doesn\'t fit in 32 bits");
        return uint32(value);
    }

    function toUint16(uint256 value) internal pure returns (uint16) {
        require(value < 2**16, "SafeCast: value doesn\'t fit in 16 bits");
        return uint16(value);
    }

    function toUint8(uint256 value) internal pure returns (uint8) {
        require(value < 2**8, "SafeCast: value doesn\'t fit in 8 bits");
        return uint8(value);
    }

    function toUint256(int256 value) internal pure returns (uint256) {
        require(value >= 0, "SafeCast: value must be positive");
        return uint256(value);
    }

    function toInt128(int256 value) internal pure returns (int128) {
        require(value >= -2**127 && value < 2**127, "SafeCast: value doesn\'t fit in 128 bits");
        return int128(value);
    }

    function toInt64(int256 value) internal pure returns (int64) {
        require(value >= -2**63 && value < 2**63, "SafeCast: value doesn\'t fit in 64 bits");
        return int64(value);
    }

    function toInt32(int256 value) internal pure returns (int32) {
        require(value >= -2**31 && value < 2**31, "SafeCast: value doesn\'t fit in 32 bits");
        return int32(value);
    }

    function toInt16(int256 value) internal pure returns (int16) {
        require(value >= -2**15 && value < 2**15, "SafeCast: value doesn\'t fit in 16 bits");
        return int16(value);
    }

    function toInt8(int256 value) internal pure returns (int8) {
        require(value >= -2**7 && value < 2**7, "SafeCast: value doesn\'t fit in 8 bits");
        return int8(value);
    }

    function toInt256(uint256 value) internal pure returns (int256) {
        require(value < 2**255, "SafeCast: value doesn't fit in an int256");
        return int256(value);
    }
}// MIT

pragma solidity =0.8.3;


contract ERC20Initializable is Initializable, IERC20, IERC20Metadata {
    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    function __ERC20_init(string memory name_, string memory symbol_) internal initializer {
        __ERC20_init_unchained(name_, symbol_);
    }

    function __ERC20_init_unchained(string memory name_, string memory symbol_) internal initializer {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][msg.sender];
        require(currentAllowance >= amount, "SHOYU: INSUFFICIENT_ALLOWANCE");
        _approve(sender, msg.sender, currentAllowance - amount);

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(msg.sender, spender, _allowances[msg.sender][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "SHOYU: ALLOWANCE_UNDERFLOW");
        _approve(msg.sender, spender, currentAllowance - subtractedValue);

        return true;
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(sender != address(0), "SHOYU: INVALID_SENDER");
        require(recipient != address(0), "SHOYU: INVALID_RECIPIENT");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "SHOYU: INVALID_ACCOUNT");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "SHOYU: INVALID_ACCOUNT");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "SHOYU: INSUFFICIENT_BALANCE");
        _balances[account] = accountBalance - amount;
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual {
        require(owner != address(0), "SHOYU: INVALID_OWNER");
        require(spender != address(0), "SHOYU: INVALID_SPENDER");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual {}
}// MIT

pragma solidity =0.8.3;


abstract contract DividendPayingERC20 is ERC20Initializable, IDividendPayingERC20 {
    using SafeCast for uint256;
    using SafeCast for int256;
    using TokenHelper for address;

    uint256 public constant override MAGNITUDE = 2**128;

    address public override dividendToken;
    uint256 public override totalDividend;

    uint256 internal magnifiedDividendPerShare;

    function __DividendPayingERC20_init(
        string memory _name,
        string memory _symbol,
        address _dividendToken
    ) internal initializer {
        __ERC20_init(_name, _symbol);
        dividendToken = _dividendToken;
    }

    mapping(address => int256) internal magnifiedDividendCorrections;
    mapping(address => uint256) internal withdrawnDividends;

    receive() external payable {
        if (msg.value > 0) {
            require(dividendToken == TokenHelper.ETH, "SHOYU: UNABLE_TO_RECEIVE_ETH");
            sync();
        }
    }

    function sync() public payable override returns (uint256 increased) {
        uint256 _totalSupply = totalSupply();
        require(_totalSupply > 0, "SHOYU: NO_SUPPLY");

        uint256 balance = dividendToken.balanceOf(address(this));
        increased = balance - totalDividend;
        require(increased > 0, "SHOYU: INSUFFICIENT_AMOUNT");

        magnifiedDividendPerShare += (increased * MAGNITUDE) / _totalSupply;
        totalDividend = balance;

        emit Sync(increased);
    }

    function withdrawDividend() public override {
        uint256 _withdrawableDividend = withdrawableDividendOf(msg.sender);
        if (_withdrawableDividend > 0) {
            withdrawnDividends[msg.sender] += _withdrawableDividend;
            emit DividendWithdrawn(msg.sender, _withdrawableDividend);
            totalDividend -= _withdrawableDividend;
            dividendToken.safeTransfer(msg.sender, _withdrawableDividend);
        }
    }

    function dividendOf(address account) public view override returns (uint256) {
        return withdrawableDividendOf(account);
    }

    function withdrawableDividendOf(address account) public view override returns (uint256) {
        return accumulativeDividendOf(account) - withdrawnDividends[account];
    }

    function withdrawnDividendOf(address account) public view override returns (uint256) {
        return withdrawnDividends[account];
    }

    function accumulativeDividendOf(address account) public view override returns (uint256) {
        return
            ((magnifiedDividendPerShare * balanceOf(account)).toInt256() + magnifiedDividendCorrections[account])
                .toUint256() / MAGNITUDE;
    }

    function _transfer(
        address from,
        address to,
        uint256 value
    ) internal override {
        super._transfer(from, to, value);

        int256 _magCorrection = (magnifiedDividendPerShare * value).toInt256();
        magnifiedDividendCorrections[from] += _magCorrection;
        magnifiedDividendCorrections[to] -= _magCorrection;
    }

    function _mint(address account, uint256 value) internal override {
        super._mint(account, value);

        magnifiedDividendCorrections[account] -= (magnifiedDividendPerShare * value).toInt256();
    }

    function _burn(address account, uint256 value) internal override {
        super._burn(account, value);

        magnifiedDividendCorrections[account] += (magnifiedDividendPerShare * value).toInt256();
    }
}// MIT

pragma solidity =0.8.3;



contract SocialTokenV0 is DividendPayingERC20, OwnableInitializable, ISocialToken {
    bytes32 public constant override PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    bytes32 internal _DOMAIN_SEPARATOR;
    uint256 internal _CACHED_CHAIN_ID;
    address internal _factory;

    mapping(address => uint256) public override nonces;

    function initialize(
        address _owner,
        string memory _name,
        string memory _symbol,
        address _dividendToken,
        uint256 initialSupply
    ) external override initializer {
        __Ownable_init(_owner);
        __DividendPayingERC20_init(_name, _symbol, _dividendToken);
        _factory = msg.sender;
        _mint(_owner, initialSupply);

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function factory() public view override returns (address) {
        return _factory;
    }

    function mint(address account, uint256 value) external override {
        require(owner() == msg.sender || _factory == msg.sender, "SHOYU: FORBIDDEN");

        _mint(account, value);
    }

    function burn(
        uint256 value,
        uint256 label,
        bytes32 data
    ) external override {
        _burn(msg.sender, value);

        emit Burn(value, label, data);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(block.timestamp <= deadline, "SHOYU: EXPIRED");
        require(owner != address(0), "SHOYU: INVALID_ADDRESS");
        require(spender != owner, "SHOYU: NOT_NECESSARY");

        bytes32 hash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        Signature.verify(hash, owner, v, r, s, DOMAIN_SEPARATOR());

        _approve(owner, spender, value);
    }
}// MIT

pragma solidity ^0.8.0;


contract ERC1155 is Context, ERC165, IERC1155, IERC1155MetadataURI {
    using Address for address;

    mapping (uint256 => mapping(address => uint256)) private _balances;

    mapping (address => mapping(address => bool)) private _operatorApprovals;

    string private _uri;

    constructor (string memory uri_) {
        _setURI(uri_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155).interfaceId
            || interfaceId == type(IERC1155MetadataURI).interfaceId
            || super.supportsInterface(interfaceId);
    }

    function uri(uint256) public view virtual override returns (string memory) {
        return _uri;
    }

    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(account != address(0), "ERC1155: balance query for the zero address");
        return _balances[id][account];
    }

    function balanceOfBatch(
        address[] memory accounts,
        uint256[] memory ids
    )
        public
        view
        virtual
        override
        returns (uint256[] memory)
    {
        require(accounts.length == ids.length, "ERC1155: accounts and ids length mismatch");

        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; ++i) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(_msgSender() != operator, "ERC1155: setting approval status for self");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[account][operator];
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        public
        virtual
        override
    {
        require(to != address(0), "ERC1155: transfer to the zero address");
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, from, to, _asSingletonArray(id), _asSingletonArray(amount), data);

        uint256 fromBalance = _balances[id][from];
        require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");
        _balances[id][from] = fromBalance - amount;
        _balances[id][to] += amount;

        emit TransferSingle(operator, from, to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        public
        virtual
        override
    {
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");
        require(to != address(0), "ERC1155: transfer to the zero address");
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            "ERC1155: transfer caller is not owner nor approved"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, from, to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");
            _balances[id][from] = fromBalance - amount;
            _balances[id][to] += amount;
        }

        emit TransferBatch(operator, from, to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);
    }

    function _setURI(string memory newuri) internal virtual {
        _uri = newuri;
    }

    function _mint(address account, uint256 id, uint256 amount, bytes memory data) internal virtual {
        require(account != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), account, _asSingletonArray(id), _asSingletonArray(amount), data);

        _balances[id][account] += amount;
        emit TransferSingle(operator, address(0), account, id, amount);

        _doSafeTransferAcceptanceCheck(operator, address(0), account, id, amount, data);
    }

    function _mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) internal virtual {
        require(to != address(0), "ERC1155: mint to the zero address");
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        for (uint i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }

        emit TransferBatch(operator, address(0), to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, data);
    }

    function _burn(address account, uint256 id, uint256 amount) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, account, address(0), _asSingletonArray(id), _asSingletonArray(amount), "");

        uint256 accountBalance = _balances[id][account];
        require(accountBalance >= amount, "ERC1155: burn amount exceeds balance");
        _balances[id][account] = accountBalance - amount;

        emit TransferSingle(operator, account, address(0), id, amount);
    }

    function _burnBatch(address account, uint256[] memory ids, uint256[] memory amounts) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, account, address(0), ids, amounts, "");

        for (uint i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 accountBalance = _balances[id][account];
            require(accountBalance >= amount, "ERC1155: burn amount exceeds balance");
            _balances[id][account] = accountBalance - amount;
        }

        emit TransferBatch(operator, account, address(0), ids, amounts);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal
        virtual
    { }

    function _doSafeTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
                if (response != IERC1155Receiver(to).onERC1155Received.selector) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _doSafeBatchTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (bytes4 response) {
                if (response != IERC1155Receiver(to).onERC1155BatchReceived.selector) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {
        uint256[] memory array = new uint256[](1);
        array[0] = element;

        return array;
    }
}// MIT

pragma solidity =0.8.3;


contract ERC1155RoyaltyMock is ERC1155("MOCK") {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external {
        _mint(account, id, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        _mintBatch(to, ids, amounts, data);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == 0x2a55205a || super.supportsInterface(interfaceId);
    }

    function royaltyInfo(uint256 _tokenId, uint256 _salePrice) external view returns (address, uint256) {
        uint256 fee = 100;
        if (_tokenId < 10) fee = 10;
        return (owner, (_salePrice * fee) / 1000);
    }
}// MIT

pragma solidity =0.8.3;


contract ERC1155Mock is ERC1155("MOCK") {
    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external {
        _mint(account, id, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        _mintBatch(to, ids, amounts, data);
    }
}// MIT

pragma solidity =0.8.3;



contract ERC1155ExchangeV0 is BaseExchange {
    bytes32 internal immutable _DOMAIN_SEPARATOR;
    uint256 internal immutable _CACHED_CHAIN_ID;
    address internal immutable _factory;

    constructor(address factory_) {
        __BaseNFTExchange_init();
        _factory = factory_;

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function factory() public view override returns (address) {
        return _factory;
    }

    function canTrade(address nft) public view override returns (bool) {
        return !ITokenFactory(_factory).isNFT1155(nft);
    }

    function _transfer(
        address nft,
        address from,
        address to,
        uint256 tokenId,
        uint256 amount
    ) internal override {
        IERC1155(nft).safeTransferFrom(from, to, tokenId, amount, "");
    }
}// MIT

pragma solidity =0.8.3;



contract ERC721ExchangeV0 is BaseExchange {
    bytes32 internal immutable _DOMAIN_SEPARATOR;
    uint256 internal immutable _CACHED_CHAIN_ID;
    address internal immutable _factory;

    constructor(address factory_) {
        __BaseNFTExchange_init();
        _factory = factory_;

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        bytes32 domainSeparator;
        if (_CACHED_CHAIN_ID == block.chainid) domainSeparator = _DOMAIN_SEPARATOR;
        else {
            domainSeparator = keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(Strings.toHexString(uint160(address(this))))),
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1"))
                    block.chainid,
                    address(this)
                )
            );
        }
        return domainSeparator;
    }

    function factory() public view override returns (address) {
        return _factory;
    }

    function canTrade(address nft) public view override returns (bool) {
        return !ITokenFactory(_factory).isNFT721(nft);
    }

    function _transfer(
        address nft,
        address from,
        address to,
        uint256 tokenId,
        uint256
    ) internal override {
        IERC721(nft).safeTransferFrom(from, to, tokenId);
    }
}// MIT

pragma solidity =0.8.3;


contract ERC721Mock is ERC721("Mock", "MOCK") {
    function safeMint(
        address to,
        uint256 tokenId,
        bytes memory data
    ) external {
        _safeMint(to, tokenId, data);
    }

    function safeMintBatch0(
        address[] calldata to,
        uint256[] calldata tokenId,
        bytes memory data
    ) external {
        require(to.length == tokenId.length);
        for (uint256 i = 0; i < to.length; i++) {
            _safeMint(to[i], tokenId[i], data);
        }
    }

    function safeMintBatch1(
        address to,
        uint256[] calldata tokenId,
        bytes memory data
    ) external {
        for (uint256 i = 0; i < tokenId.length; i++) {
            _safeMint(to, tokenId[i], data);
        }
    }
}// MIT

pragma solidity ^0.8.0;


contract ERC20 is Context, IERC20, IERC20Metadata {
    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    constructor (string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(sender, _msgSender(), currentAllowance - amount);

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        _approve(_msgSender(), spender, currentAllowance - subtractedValue);

        return true;
    }

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        _balances[account] = accountBalance - amount;
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
}// MIT

pragma solidity =0.8.3;


contract ERC20Mock is ERC20("Mock", "MOCK") {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}// MIT

pragma solidity >=0.5.0;


interface IERC20Snapshot is IERC20, IERC20Metadata {
    function balanceOfAt(address account, uint256 snapshotId) external view returns (uint256);

    function totalSupplyAt(uint256 snapshotId) external view returns (uint256);
}// MIT

pragma solidity =0.8.3;


contract FixedPriceSale is IStrategy {
    function canClaim(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address,
        uint256 bidPrice,
        address,
        uint256,
        uint256
    ) external view override returns (bool) {
        uint256 price = abi.decode(params, (uint256));
        require(price > 0, "SHOYU: INVALID_PRICE");
        return (proxy != address(0) || block.timestamp <= deadline) && bidPrice == price;
    }

    function canBid(
        address,
        uint256,
        bytes memory,
        address,
        uint256,
        address,
        uint256,
        uint256
    ) external pure override returns (bool) {
        return false;
    }
}// MIT

pragma solidity =0.8.3;


contract EnglishAuction is IStrategy {
    function canClaim(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address bidder,
        uint256 bidPrice,
        address bestBidder,
        uint256 bestBidPrice,
        uint256
    ) external view override returns (bool) {
        if (proxy == address(0)) {
            return bidder == bestBidder && bidPrice == bestBidPrice && deadline < block.timestamp;
        } else {
            uint256 startPrice = abi.decode(params, (uint256));
            require(startPrice > 0, "SHOYU: INVALID_START_PRICE");

            return bidPrice >= startPrice && deadline < block.timestamp;
        }
    }

    function canBid(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address,
        uint256 bidPrice,
        address,
        uint256 bestBidPrice,
        uint256
    ) external view override returns (bool) {
        if (proxy == address(0)) {
            uint256 startPrice = abi.decode(params, (uint256));
            require(startPrice > 0, "SHOYU: INVALID_START_PRICE");

            return block.timestamp <= deadline && bidPrice >= startPrice && bidPrice > bestBidPrice;
        } else {
            return false;
        }
    }
}// MIT

pragma solidity =0.8.3;


contract DutchAuction is IStrategy {
    function canClaim(
        address proxy,
        uint256 deadline,
        bytes memory params,
        address,
        uint256 bidPrice,
        address,
        uint256,
        uint256
    ) external view override returns (bool) {
        (uint256 startPrice, uint256 endPrice, uint256 startedAt) = abi.decode(params, (uint256, uint256, uint256));
        require(startPrice > endPrice, "SHOYU: INVALID_PRICE_RANGE");
        require(startedAt < deadline, "SHOYU: INVALID_STARTED_AT");

        uint256 tickPerBlock = (startPrice - endPrice) / (deadline - startedAt);
        uint256 currentPrice =
            block.timestamp >= deadline ? endPrice : startPrice - ((block.timestamp - startedAt) * tickPerBlock);

        return (proxy != address(0) || block.timestamp <= deadline) && bidPrice >= currentPrice;
    }

    function canBid(
        address,
        uint256,
        bytes memory,
        address,
        uint256,
        address,
        uint256,
        uint256
    ) external pure override returns (bool) {
        return false;
    }
}