
pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;



library EIP712
{

    struct Domain {
        string  name;
        string  version;
        address verifyingContract;
    }

    bytes32 constant internal EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    string constant internal EIP191_HEADER = "\x19\x01";

    function hash(Domain memory domain)
        internal
        pure
        returns (bytes32)
    {

        uint _chainid;
        assembly { _chainid := chainid() }

        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(domain.name)),
                keccak256(bytes(domain.version)),
                _chainid,
                domain.verifyingContract
            )
        );
    }

    function hashPacked(
        bytes32 domainHash,
        bytes32 dataHash
        )
        internal
        pure
        returns (bytes32)
    {

        return keccak256(
            abi.encodePacked(
                EIP191_HEADER,
                domainHash,
                dataHash
            )
        );
    }
}



interface IAgent{}


abstract contract IAgentRegistry
{
    function isAgent(
        address owner,
        address agent
        )
        external
        virtual
        view
        returns (bool);


    function isAgent(
        address[] calldata owners,
        address            agent
        )
        external
        virtual
        view
        returns (bool);


    function isUniversalAgent(address agent)
        public
        virtual
        view
        returns (bool);

}




contract Ownable
{

    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    constructor()
    {
        owner = msg.sender;
    }

    modifier onlyOwner()
    {

        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    function transferOwnership(
        address newOwner
        )
        public
        virtual
        onlyOwner
    {

        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function renounceOwnership()
        public
        onlyOwner
    {

        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
    }
}





contract Claimable is Ownable
{

    address public pendingOwner;

    modifier onlyPendingOwner() {

        require(msg.sender == pendingOwner, "UNAUTHORIZED");
        _;
    }

    function transferOwnership(
        address newOwner
        )
        public
        override
        onlyOwner
    {

        require(newOwner != address(0) && newOwner != owner, "INVALID_ADDRESS");
        pendingOwner = newOwner;
    }

    function claimOwnership()
        public
        onlyPendingOwner
    {

        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}





abstract contract IBlockVerifier is Claimable
{

    event CircuitRegistered(
        uint8  indexed blockType,
        uint16         blockSize,
        uint8          blockVersion
    );

    event CircuitDisabled(
        uint8  indexed blockType,
        uint16         blockSize,
        uint8          blockVersion
    );


    function registerCircuit(
        uint8    blockType,
        uint16   blockSize,
        uint8    blockVersion,
        uint[18] calldata vk
        )
        external
        virtual;

    function disableCircuit(
        uint8  blockType,
        uint16 blockSize,
        uint8  blockVersion
        )
        external
        virtual;

    function verifyProofs(
        uint8  blockType,
        uint16 blockSize,
        uint8  blockVersion,
        uint[] calldata publicInputs,
        uint[] calldata proofs
        )
        external
        virtual
        view
        returns (bool);

    function isCircuitRegistered(
        uint8  blockType,
        uint16 blockSize,
        uint8  blockVersion
        )
        external
        virtual
        view
        returns (bool);

    function isCircuitEnabled(
        uint8  blockType,
        uint16 blockSize,
        uint8  blockVersion
        )
        external
        virtual
        view
        returns (bool);
}




interface IDepositContract
{

    function isTokenSupported(address token)
        external
        view
        returns (bool);


    function deposit(
        address from,
        address token,
        uint96  amount,
        bytes   calldata extraData
        )
        external
        payable
        returns (uint96 amountReceived);


    function withdraw(
        address from,
        address to,
        address token,
        uint    amount,
        bytes   calldata extraData
        )
        external
        payable;


    function transfer(
        address from,
        address to,
        address token,
        uint    amount
        )
        external
        payable;


    function isETH(address addr)
        external
        view
        returns (bool);

}





abstract contract ILoopringV3 is Claimable
{
    event ExchangeStakeDeposited(address exchangeAddr, uint amount);
    event ExchangeStakeWithdrawn(address exchangeAddr, uint amount);
    event ExchangeStakeBurned(address exchangeAddr, uint amount);
    event SettingsUpdated(uint time);

    mapping (address => uint) internal exchangeStake;

    uint    public totalStake;
    address public blockVerifierAddress;
    uint    public forcedWithdrawalFee;
    uint    public tokenRegistrationFeeLRCBase;
    uint    public tokenRegistrationFeeLRCDelta;
    uint8   public protocolTakerFeeBips;
    uint8   public protocolMakerFeeBips;

    address payable public protocolFeeVault;


    function lrcAddress()
        external
        view
        virtual
        returns (address);

    function updateSettings(
        address payable _protocolFeeVault,   // address(0) not allowed
        address _blockVerifierAddress,       // address(0) not allowed
        uint    _forcedWithdrawalFee
        )
        external
        virtual;

    function updateProtocolFeeSettings(
        uint8 _protocolTakerFeeBips,
        uint8 _protocolMakerFeeBips
        )
        external
        virtual;

    function getExchangeStake(
        address exchangeAddr
        )
        public
        virtual
        view
        returns (uint stakedLRC);

    function burnExchangeStake(
        uint amount
        )
        external
        virtual
        returns (uint burnedLRC);

    function depositExchangeStake(
        address exchangeAddr,
        uint    amountLRC
        )
        external
        virtual
        returns (uint stakedLRC);

    function withdrawExchangeStake(
        address recipient,
        uint    requestedAmount
        )
        external
        virtual
        returns (uint amountLRC);

    function getProtocolFeeValues(
        )
        public
        virtual
        view
        returns (
            uint8 takerFeeBips,
            uint8 makerFeeBips
        );
}








library ExchangeData
{

    enum TransactionType
    {
        NOOP,
        DEPOSIT,
        WITHDRAWAL,
        TRANSFER,
        SPOT_TRADE,
        ACCOUNT_UPDATE,
        AMM_UPDATE,
        SIGNATURE_VERIFICATION
    }

    struct Token
    {
        address token;
    }

    struct ProtocolFeeData
    {
        uint32 syncedAt; // only valid before 2105 (85 years to go)
        uint8  takerFeeBips;
        uint8  makerFeeBips;
        uint8  previousTakerFeeBips;
        uint8  previousMakerFeeBips;
    }

    struct AuxiliaryData
    {
        uint  txIndex;
        bool  approved;
        bytes data;
    }

    struct Block
    {
        uint8      blockType;
        uint16     blockSize;
        uint8      blockVersion;
        bytes      data;
        uint256[8] proof;

        bool storeBlockInfoOnchain;

        AuxiliaryData[] auxiliaryData;

        bytes offchainData;
    }

    struct BlockInfo
    {
        uint32  timestamp;
        bytes28 blockDataHash;
    }

    struct Deposit
    {
        uint96 amount;
        uint64 timestamp;
    }

    struct ForcedWithdrawal
    {
        address owner;
        uint64  timestamp;
    }

    struct Constants
    {
        uint SNARK_SCALAR_FIELD;
        uint MAX_OPEN_FORCED_REQUESTS;
        uint MAX_AGE_FORCED_REQUEST_UNTIL_WITHDRAW_MODE;
        uint TIMESTAMP_HALF_WINDOW_SIZE_IN_SECONDS;
        uint MAX_NUM_ACCOUNTS;
        uint MAX_NUM_TOKENS;
        uint MIN_AGE_PROTOCOL_FEES_UNTIL_UPDATED;
        uint MIN_TIME_IN_SHUTDOWN;
        uint TX_DATA_AVAILABILITY_SIZE;
        uint MAX_AGE_DEPOSIT_UNTIL_WITHDRAWABLE_UPPERBOUND;
    }

    function SNARK_SCALAR_FIELD() internal pure returns (uint) {

        return 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }
    function MAX_OPEN_FORCED_REQUESTS() internal pure returns (uint16) { return 4096; }

    function MAX_AGE_FORCED_REQUEST_UNTIL_WITHDRAW_MODE() internal pure returns (uint32) { return 15 days; }

    function TIMESTAMP_HALF_WINDOW_SIZE_IN_SECONDS() internal pure returns (uint32) { return 7 days; }

    function MAX_NUM_ACCOUNTS() internal pure returns (uint) { return 2 ** 32; }

    function MAX_NUM_TOKENS() internal pure returns (uint) { return 2 ** 16; }

    function MIN_AGE_PROTOCOL_FEES_UNTIL_UPDATED() internal pure returns (uint32) { return 7 days; }

    function MIN_TIME_IN_SHUTDOWN() internal pure returns (uint32) { return 30 days; }

    function TX_DATA_AVAILABILITY_SIZE() internal pure returns (uint32) { return 68; }

    function MAX_AGE_DEPOSIT_UNTIL_WITHDRAWABLE_UPPERBOUND() internal pure returns (uint32) { return 15 days; }

    function ACCOUNTID_PROTOCOLFEE() internal pure returns (uint32) { return 0; }


    function TX_DATA_AVAILABILITY_SIZE_PART_1() internal pure returns (uint32) { return 29; }

    function TX_DATA_AVAILABILITY_SIZE_PART_2() internal pure returns (uint32) { return 39; }


    struct AccountLeaf
    {
        uint32   accountID;
        address  owner;
        uint     pubKeyX;
        uint     pubKeyY;
        uint32   nonce;
        uint     feeBipsAMM;
    }

    struct BalanceLeaf
    {
        uint16   tokenID;
        uint96   balance;
        uint96   weightAMM;
        uint     storageRoot;
    }

    struct MerkleProof
    {
        ExchangeData.AccountLeaf accountLeaf;
        ExchangeData.BalanceLeaf balanceLeaf;
        uint[48]                 accountMerkleProof;
        uint[24]                 balanceMerkleProof;
    }

    struct BlockContext
    {
        bytes32 DOMAIN_SEPARATOR;
        uint32  timestamp;
    }

    struct State
    {
        uint32  maxAgeDepositUntilWithdrawable;
        bytes32 DOMAIN_SEPARATOR;

        ILoopringV3      loopring;
        IBlockVerifier   blockVerifier;
        IAgentRegistry   agentRegistry;
        IDepositContract depositContract;


        bytes32 merkleRoot;

        mapping(uint => BlockInfo) blocks;
        uint  numBlocks;

        Token[] tokens;

        mapping (address => uint16) tokenToTokenId;

        mapping (uint32 => mapping (uint16 => bool)) withdrawnInWithdrawMode;

        mapping (address => mapping (uint16 => uint)) amountWithdrawable;

        mapping (uint32 => mapping (uint16 => ForcedWithdrawal)) pendingForcedWithdrawals;

        mapping (address => mapping (uint16 => Deposit)) pendingDeposits;

        mapping (address => mapping (bytes32 => bool)) approvedTx;

        mapping (address => mapping (address => mapping (uint16 => mapping (uint => mapping (uint32 => address))))) withdrawalRecipient;


        uint32 numPendingForcedTransactions;

        ProtocolFeeData protocolFeeData;

        uint shutdownModeStartTime;

        uint withdrawalModeStartTime;

        mapping (address => uint) protocolFeeLastWithdrawnTime;
    }
}






abstract contract IExchangeV3 is Claimable
{

    event ExchangeCloned(
        address exchangeAddress,
        address owner,
        bytes32 genesisMerkleRoot
    );

    event TokenRegistered(
        address token,
        uint16  tokenId
    );

    event Shutdown(
        uint timestamp
    );

    event WithdrawalModeActivated(
        uint timestamp
    );

    event BlockSubmitted(
        uint    indexed blockIdx,
        bytes32         merkleRoot,
        bytes32         publicDataHash
    );

    event DepositRequested(
        address from,
        address to,
        address token,
        uint16  tokenId,
        uint96  amount
    );

    event ForcedWithdrawalRequested(
        address owner,
        address token,
        uint32  accountID
    );

    event WithdrawalCompleted(
        uint8   category,
        address from,
        address to,
        address token,
        uint    amount
    );

    event WithdrawalFailed(
        uint8   category,
        address from,
        address to,
        address token,
        uint    amount
    );

    event ProtocolFeesUpdated(
        uint8 takerFeeBips,
        uint8 makerFeeBips,
        uint8 previousTakerFeeBips,
        uint8 previousMakerFeeBips
    );

    event TransactionApproved(
        address owner,
        bytes32 transactionHash
    );


    function initialize(
        address loopring,
        address owner,
        bytes32 genesisMerkleRoot
        )
        virtual
        external;

    function setAgentRegistry(address agentRegistry)
        external
        virtual;

    function getAgentRegistry()
        external
        virtual
        view
        returns (IAgentRegistry);

    function setDepositContract(address depositContract)
        external
        virtual;

    function refreshBlockVerifier()
        external
        virtual;

    function getDepositContract()
        external
        virtual
        view
        returns (IDepositContract);

    function withdrawExchangeFees(
        address token,
        address feeRecipient
        )
        external
        virtual;

    function getConstants()
        external
        virtual
        pure
        returns(ExchangeData.Constants memory);

    function isInWithdrawalMode()
        external
        virtual
        view
        returns (bool);

    function isShutdown()
        external
        virtual
        view
        returns (bool);

    function registerToken(
        address tokenAddress
        )
        external
        virtual
        returns (uint16 tokenID);

    function getTokenID(
        address tokenAddress
        )
        external
        virtual
        view
        returns (uint16 tokenID);

    function getTokenAddress(
        uint16 tokenID
        )
        external
        virtual
        view
        returns (address tokenAddress);

    function getExchangeStake()
        external
        virtual
        view
        returns (uint);

    function withdrawExchangeStake(
        address recipient
        )
        external
        virtual
        returns (uint amountLRC);

    function burnExchangeStake()
        external
        virtual;


    function getMerkleRoot()
        external
        virtual
        view
        returns (bytes32);

    function getBlockHeight()
        external
        virtual
        view
        returns (uint);

    function getBlockInfo(uint blockIdx)
        external
        virtual
        view
        returns (ExchangeData.BlockInfo memory);

    function submitBlocks(ExchangeData.Block[] calldata blocks)
        external
        virtual;

    function getNumAvailableForcedSlots()
        external
        virtual
        view
        returns (uint);


    function deposit(
        address from,
        address to,
        address tokenAddress,
        uint96  amount,
        bytes   calldata auxiliaryData
        )
        external
        virtual
        payable;

    function getPendingDepositAmount(
        address owner,
        address tokenAddress
        )
        external
        virtual
        view
        returns (uint96);

    function forceWithdraw(
        address owner,
        address tokenAddress,
        uint32  accountID
        )
        external
        virtual
        payable;

    function isForcedWithdrawalPending(
        uint32  accountID,
        address token
        )
        external
        virtual
        view
        returns (bool);

    function withdrawProtocolFees(
        address tokenAddress
        )
        external
        virtual
        payable;

    function getProtocolFeeLastWithdrawnTime(
        address tokenAddress
        )
        external
        virtual
        view
        returns (uint);

    function withdrawFromMerkleTree(
        ExchangeData.MerkleProof calldata merkleProof
        )
        external
        virtual;

    function isWithdrawnInWithdrawalMode(
        uint32  accountID,
        address token
        )
        external
        virtual
        view
        returns (bool);

    function withdrawFromDepositRequest(
        address owner,
        address token
        )
        external
        virtual;

    function withdrawFromApprovedWithdrawals(
        address[] calldata owners,
        address[] calldata tokens
        )
        external
        virtual;

    function getAmountWithdrawable(
        address owner,
        address token
        )
        external
        virtual
        view
        returns (uint);

    function notifyForcedRequestTooOld(
        uint32  accountID,
        address token
        )
        external
        virtual;

    function setWithdrawalRecipient(
        address from,
        address to,
        address token,
        uint96  amount,
        uint32  storageID,
        address newRecipient
        )
        external
        virtual;

    function getWithdrawalRecipient(
        address from,
        address to,
        address token,
        uint96  amount,
        uint32  storageID
        )
        external
        virtual
        view
        returns (address);

    function onchainTransferFrom(
        address from,
        address to,
        address token,
        uint    amount
        )
        external
        virtual;

    function approveTransaction(
        address owner,
        bytes32 txHash
        )
        external
        virtual;

    function approveTransactions(
        address[] calldata owners,
        bytes32[] calldata txHashes
        )
        external
        virtual;

    function isTransactionApproved(
        address owner,
        bytes32 txHash
        )
        external
        virtual
        view
        returns (bool);

    function setMaxAgeDepositUntilWithdrawable(
        uint32 newValue
        )
        external
        virtual
        returns (uint32);

    function getMaxAgeDepositUntilWithdrawable()
        external
        virtual
        view
        returns (uint32);

    function shutdown()
        external
        virtual
        returns (bool success);

    function getProtocolFeeValues()
        external
        virtual
        view
        returns (
            uint32 syncedAt,
            uint8 takerFeeBips,
            uint8 makerFeeBips,
            uint8 previousTakerFeeBips,
            uint8 previousMakerFeeBips
        );

    function getDomainSeparator()
        external
        virtual
        view
        returns (bytes32);
}



interface IAmmSharedConfig
{

    function maxForcedExitAge() external view returns (uint);

    function maxForcedExitCount() external view returns (uint);

    function forcedExitFee() external view returns (uint);

}







library AmmData
{

    function POOL_TOKEN_BASE() internal pure returns (uint) { return 100 * (10 ** 8); }

    function POOL_TOKEN_MINTED_SUPPLY() internal pure returns (uint) { return uint96(-1); }


    enum PoolTxType
    {
        NOOP,
        JOIN,
        EXIT
    }

    struct PoolConfig
    {
        address   sharedConfig;
        address   exchange;
        string    poolName;
        uint32    accountID;
        address[] tokens;
        uint96[]  weights;
        uint8     feeBips;
        string    tokenSymbol;
    }

    struct PoolJoin
    {
        address   owner;
        uint96[]  joinAmounts;
        uint32[]  joinStorageIDs;
        uint96    mintMinAmount;
        uint32    validUntil;
    }

    struct PoolExit
    {
        address   owner;
        uint96    burnAmount;
        uint32    burnStorageID; // for pool token withdrawal from user to the pool
        uint96[]  exitMinAmounts; // the amount to receive BEFORE paying the fee.
        uint96    fee;
        uint32    validUntil;
    }

    struct PoolTx
    {
        PoolTxType txType;
        bytes      data;
        bytes      signature;
    }

    struct Token
    {
        address addr;
        uint96  weight;
        uint16  tokenID;
    }

    struct Context
    {
        uint txIdx;

        IExchangeV3 exchange;
        bytes32     exchangeDomainSeparator;

        bytes32 domainSeparator;
        uint32  accountID;

        uint16  poolTokenID;
        uint    totalSupply;

        Token[]  tokens;
        uint96[] tokenBalancesL2;
    }

    struct State {
        string poolName;
        string symbol;
        uint   _totalSupply;

        mapping(address => uint) balanceOf;
        mapping(address => mapping(address => uint)) allowance;
        mapping(address => uint) nonces;

        IAmmSharedConfig sharedConfig;

        Token[]     tokens;

        bytes32     exchangeDomainSeparator;
        bytes32     domainSeparator;
        IExchangeV3 exchange;
        uint32      accountID;
        uint16      poolTokenID;
        uint8       feeBips;

        address     exchangeOwner;

        uint64      shutdownTimestamp;
        uint16      forcedExitCount;

        mapping (address => PoolExit) forcedExit;
        mapping (bytes32 => bool) approvedTx;
    }
}



library BytesUtil {


    function concat(
        bytes memory _preBytes,
        bytes memory _postBytes
    )
        internal
        pure
        returns (bytes memory)
    {

        bytes memory tempBytes;

        assembly {
            tempBytes := mload(0x40)

            let length := mload(_preBytes)
            mstore(tempBytes, length)

            let mc := add(tempBytes, 0x20)
            let end := add(mc, length)

            for {
                let cc := add(_preBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            length := mload(_postBytes)
            mstore(tempBytes, add(length, mload(tempBytes)))

            mc := end
            end := add(mc, length)

            for {
                let cc := add(_postBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            mstore(0x40, and(
              add(add(end, iszero(add(length, mload(_preBytes)))), 31),
              not(31) // Round down to the nearest 32 bytes.
            ))
        }

        return tempBytes;
    }

    function slice(
        bytes memory _bytes,
        uint _start,
        uint _length
    )
        internal
        pure
        returns (bytes memory)
    {

        require(_bytes.length >= (_start + _length));

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                tempBytes := mload(0x40)

                let lengthmod := and(_length, 31)

                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                mstore(0x40, and(add(mc, 31), not(31)))
            }
            default {
                tempBytes := mload(0x40)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    function toAddress(bytes memory _bytes, uint _start) internal  pure returns (address) {

        require(_bytes.length >= (_start + 20));
        address tempAddress;

        assembly {
            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)
        }

        return tempAddress;
    }

    function toUint8(bytes memory _bytes, uint _start) internal  pure returns (uint8) {

        require(_bytes.length >= (_start + 1));
        uint8 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

        return tempUint;
    }

    function toUint16(bytes memory _bytes, uint _start) internal  pure returns (uint16) {

        require(_bytes.length >= (_start + 2));
        uint16 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x2), _start))
        }

        return tempUint;
    }

    function toUint24(bytes memory _bytes, uint _start) internal  pure returns (uint24) {

        require(_bytes.length >= (_start + 3));
        uint24 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x3), _start))
        }

        return tempUint;
    }

    function toUint32(bytes memory _bytes, uint _start) internal  pure returns (uint32) {

        require(_bytes.length >= (_start + 4));
        uint32 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x4), _start))
        }

        return tempUint;
    }

    function toUint64(bytes memory _bytes, uint _start) internal  pure returns (uint64) {

        require(_bytes.length >= (_start + 8));
        uint64 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x8), _start))
        }

        return tempUint;
    }

    function toUint96(bytes memory _bytes, uint _start) internal  pure returns (uint96) {

        require(_bytes.length >= (_start + 12));
        uint96 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0xc), _start))
        }

        return tempUint;
    }

    function toUint128(bytes memory _bytes, uint _start) internal  pure returns (uint128) {

        require(_bytes.length >= (_start + 16));
        uint128 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x10), _start))
        }

        return tempUint;
    }

    function toUint(bytes memory _bytes, uint _start) internal  pure returns (uint256) {

        require(_bytes.length >= (_start + 32));
        uint256 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x20), _start))
        }

        return tempUint;
    }

    function toBytes4(bytes memory _bytes, uint _start) internal  pure returns (bytes4) {

        require(_bytes.length >= (_start + 4));
        bytes4 tempBytes4;

        assembly {
            tempBytes4 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes4;
    }

    function toBytes20(bytes memory _bytes, uint _start) internal  pure returns (bytes20) {

        require(_bytes.length >= (_start + 20));
        bytes20 tempBytes20;

        assembly {
            tempBytes20 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes20;
    }

    function toBytes32(bytes memory _bytes, uint _start) internal  pure returns (bytes32) {

        require(_bytes.length >= (_start + 32));
        bytes32 tempBytes32;

        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes32;
    }

    function fastSHA256(
        bytes memory data
        )
        internal
        view
        returns (bytes32)
    {

        bytes32[] memory result = new bytes32[](1);
        bool success;
        assembly {
             let ptr := add(data, 32)
             success := staticcall(sub(gas(), 2000), 2, ptr, mload(data), add(result, 32), 32)
        }
        require(success, "SHA256_FAILED");
        return result[0];
    }
}





library BlockReader {

    using BlockReader       for ExchangeData.Block;
    using BytesUtil         for bytes;

    uint public constant OFFSET_TO_TRANSACTIONS = 20 + 32 + 32 + 4 + 1 + 1 + 4 + 4;

    struct BlockHeader
    {
        address exchange;
        bytes32 merkleRootBefore;
        bytes32 merkleRootAfter;
        uint32  timestamp;
        uint8   protocolTakerFeeBips;
        uint8   protocolMakerFeeBips;
        uint32  numConditionalTransactions;
        uint32  operatorAccountID;
    }

    function readHeader(
        ExchangeData.Block memory _block
        )
        internal
        pure
        returns (BlockHeader memory header)
    {

        uint offset = 0;
        header.exchange = _block.data.toAddress(offset);
        offset += 20;
        header.merkleRootBefore = _block.data.toBytes32(offset);
        offset += 32;
        header.merkleRootAfter = _block.data.toBytes32(offset);
        offset += 32;
        header.timestamp = _block.data.toUint32(offset);
        offset += 4;
        header.protocolTakerFeeBips = _block.data.toUint8(offset);
        offset += 1;
        header.protocolMakerFeeBips = _block.data.toUint8(offset);
        offset += 1;
        header.numConditionalTransactions = _block.data.toUint32(offset);
        offset += 4;
        header.operatorAccountID = _block.data.toUint32(offset);
        offset += 4;
        assert(offset == OFFSET_TO_TRANSACTIONS);
    }

    function readTransactionData(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (bytes memory)
    {

        require(txIdx < _block.blockSize, "INVALID_TX_IDX");

        bytes memory data = _block.data;

        bytes memory txData = new bytes(ExchangeData.TX_DATA_AVAILABILITY_SIZE());
        uint txDataOffset = OFFSET_TO_TRANSACTIONS +
            txIdx * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_1();
        assembly {
            mstore(add(txData, 32), mload(add(data, add(txDataOffset, 32))))
        }
        txDataOffset = OFFSET_TO_TRANSACTIONS +
            _block.blockSize * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_1() +
            txIdx * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_2();
        assembly {
            mstore(add(txData, 61 /*32 + 29*/), mload(add(data, add(txDataOffset, 32))))
            mstore(add(txData, 68            ), mload(add(data, add(txDataOffset, 39))))
        }
        return txData;
    }
}




library MathUint
{

    using MathUint for uint;

    function mul(
        uint a,
        uint b
        )
        internal
        pure
        returns (uint c)
    {

        c = a * b;
        require(a == 0 || c / a == b, "MUL_OVERFLOW");
    }

    function sub(
        uint a,
        uint b
        )
        internal
        pure
        returns (uint)
    {

        require(b <= a, "SUB_UNDERFLOW");
        return a - b;
    }

    function add(
        uint a,
        uint b
        )
        internal
        pure
        returns (uint c)
    {

        c = a + b;
        require(c >= a, "ADD_OVERFLOW");
    }

    function add64(
        uint64 a,
        uint64 b
        )
        internal
        pure
        returns (uint64 c)
    {

        c = a + b;
        require(c >= a, "ADD_OVERFLOW");
    }
}




library AddressUtil
{

    using AddressUtil for *;

    function isContract(
        address addr
        )
        internal
        view
        returns (bool)
    {

        bytes32 codehash;
        assembly { codehash := extcodehash(addr) }
        return (codehash != 0x0 &&
                codehash != 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);
    }

    function toPayable(
        address addr
        )
        internal
        pure
        returns (address payable)
    {

        return payable(addr);
    }

    function sendETH(
        address to,
        uint    amount,
        uint    gasLimit
        )
        internal
        returns (bool success)
    {

        if (amount == 0) {
            return true;
        }
        address payable recipient = to.toPayable();
        (success, ) = recipient.call{value: amount, gas: gasLimit}("");
    }

    function sendETHAndVerify(
        address to,
        uint    amount,
        uint    gasLimit
        )
        internal
        returns (bool success)
    {

        success = to.sendETH(amount, gasLimit);
        require(success, "TRANSFER_FAILURE");
    }

    function fastCall(
        address to,
        uint    gasLimit,
        uint    value,
        bytes   memory data
        )
        internal
        returns (bool success, bytes memory returnData)
    {

        if (to != address(0)) {
            assembly {
                success := call(gasLimit, to, value, add(data, 32), mload(data), 0, 0)
                let size := returndatasize()
                returnData := mload(0x40)
                mstore(returnData, size)
                returndatacopy(add(returnData, 32), 0, size)
                mstore(0x40, add(returnData, add(32, size)))
            }
        }
    }

    function fastCallAndVerify(
        address to,
        uint    gasLimit,
        uint    value,
        bytes   memory data
        )
        internal
        returns (bytes memory returnData)
    {

        bool success;
        (success, returnData) = fastCall(to, gasLimit, value, data);
        if (!success) {
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }
    }
}



abstract contract ERC1271 {
    bytes4 constant internal ERC1271_MAGICVALUE = 0x1626ba7e;

    function isValidSignature(
        bytes32      _hash,
        bytes memory _signature)
        public
        view
        virtual
        returns (bytes4 magicValueB32);

}








library SignatureUtil
{

    using BytesUtil     for bytes;
    using MathUint      for uint;
    using AddressUtil   for address;

    enum SignatureType {
        ILLEGAL,
        INVALID,
        EIP_712,
        ETH_SIGN,
        WALLET   // deprecated
    }

    bytes4 constant internal ERC1271_MAGICVALUE = 0x1626ba7e;

    function verifySignatures(
        bytes32          signHash,
        address[] memory signers,
        bytes[]   memory signatures
        )
        internal
        view
        returns (bool)
    {

        require(signers.length == signatures.length, "BAD_SIGNATURE_DATA");
        address lastSigner;
        for (uint i = 0; i < signers.length; i++) {
            require(signers[i] > lastSigner, "INVALID_SIGNERS_ORDER");
            lastSigner = signers[i];
            if (!verifySignature(signHash, signers[i], signatures[i])) {
                return false;
            }
        }
        return true;
    }

    function verifySignature(
        bytes32        signHash,
        address        signer,
        bytes   memory signature
        )
        internal
        view
        returns (bool)
    {

        if (signer == address(0)) {
            return false;
        }

        return signer.isContract()?
            verifyERC1271Signature(signHash, signer, signature):
            verifyEOASignature(signHash, signer, signature);
    }

    function recoverECDSASigner(
        bytes32      signHash,
        bytes memory signature
        )
        internal
        pure
        returns (address)
    {

        if (signature.length != 65) {
            return address(0);
        }

        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := and(mload(add(signature, 0x41)), 0xff)
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v == 27 || v == 28) {
            return ecrecover(signHash, v, r, s);
        } else {
            return address(0);
        }
    }

    function verifyEOASignature(
        bytes32        signHash,
        address        signer,
        bytes   memory signature
        )
        private
        pure
        returns (bool success)
    {

        if (signer == address(0)) {
            return false;
        }

        uint signatureTypeOffset = signature.length.sub(1);
        SignatureType signatureType = SignatureType(signature.toUint8(signatureTypeOffset));

        assembly {
            mstore(signature, signatureTypeOffset)
        }

        if (signatureType == SignatureType.EIP_712) {
            success = (signer == recoverECDSASigner(signHash, signature));
        } else if (signatureType == SignatureType.ETH_SIGN) {
            bytes32 hash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", signHash)
            );
            success = (signer == recoverECDSASigner(hash, signature));
        } else {
            success = false;
        }

        assembly {
            mstore(signature, add(signatureTypeOffset, 1))
        }

        return success;
    }

    function verifyERC1271Signature(
        bytes32 signHash,
        address signer,
        bytes   memory signature
        )
        private
        view
        returns (bool)
    {

        bytes memory callData = abi.encodeWithSelector(
            ERC1271.isValidSignature.selector,
            signHash,
            signature
        );
        (bool success, bytes memory result) = signer.staticcall(callData);
        return (
            success &&
            result.length == 32 &&
            result.toBytes4(0) == ERC1271_MAGICVALUE
        );
    }
}






library ExchangeSignatures
{

    using SignatureUtil for bytes32;

    function requireAuthorizedTx(
        ExchangeData.State storage S,
        address signer,
        bytes memory signature,
        bytes32 txHash
        )
        internal // inline call
    {

        require(signer != address(0), "INVALID_SIGNER");
        if (signature.length > 0) {
            require(txHash.verifySignature(signer, signature), "INVALID_SIGNATURE");
        } else {
            require(S.approvedTx[signer][txHash], "TX_NOT_APPROVED");
            delete S.approvedTx[signer][txHash];
        }
    }
}










library AmmUpdateTransaction
{

    using BytesUtil            for bytes;
    using MathUint             for uint;
    using ExchangeSignatures   for ExchangeData.State;

    bytes32 constant public AMMUPDATE_TYPEHASH = keccak256(
        "AmmUpdate(address owner,uint32 accountID,uint16 tokenID,uint8 feeBips,uint96 tokenWeight,uint32 validUntil,uint32 nonce)"
    );

    struct AmmUpdate
    {
        address owner;
        uint32  accountID;
        uint16  tokenID;
        uint8   feeBips;
        uint96  tokenWeight;
        uint32  validUntil;
        uint32  nonce;
        uint96  balance;
    }

    struct AmmUpdateAuxiliaryData
    {
        bytes  signature;
        uint32 validUntil;
    }

    function process(
        ExchangeData.State        storage S,
        ExchangeData.BlockContext memory  ctx,
        bytes                     memory  data,
        uint                              offset,
        bytes                     memory  auxiliaryData
        )
        internal
    {

        AmmUpdate memory update = readTx(data, offset);
        AmmUpdateAuxiliaryData memory auxData = abi.decode(auxiliaryData, (AmmUpdateAuxiliaryData));

        require(ctx.timestamp < auxData.validUntil, "AMM_UPDATE_EXPIRED");
        update.validUntil = auxData.validUntil;

        bytes32 txHash = hashTx(ctx.DOMAIN_SEPARATOR, update);

        S.requireAuthorizedTx(update.owner, auxData.signature, txHash);
    }

    function readTx(
        bytes memory data,
        uint         offset
        )
        internal
        pure
        returns (AmmUpdate memory update)
    {

        uint _offset = offset;
        update.owner = data.toAddress(_offset);
        _offset += 20;
        update.accountID = data.toUint32(_offset);
        _offset += 4;
        update.tokenID = data.toUint16(_offset);
        _offset += 2;
        update.feeBips = data.toUint8(_offset);
        _offset += 1;
        update.tokenWeight = data.toUint96(_offset);
        _offset += 12;
        update.nonce = data.toUint32(_offset);
        _offset += 4;
        update.balance = data.toUint96(_offset);
        _offset += 12;
    }

    function hashTx(
        bytes32 DOMAIN_SEPARATOR,
        AmmUpdate memory update
        )
        internal
        pure
        returns (bytes32)
    {

        return EIP712.hashPacked(
            DOMAIN_SEPARATOR,
            keccak256(
                abi.encode(
                    AMMUPDATE_TYPEHASH,
                    update.owner,
                    update.accountID,
                    update.tokenID,
                    update.feeBips,
                    update.tokenWeight,
                    update.validUntil,
                    update.nonce
                )
            )
        );
    }
}




library MathUint96
{

    function add(
        uint96 a,
        uint96 b
        )
        internal
        pure
        returns (uint96 c)
    {

        c = a + b;
        require(c >= a, "ADD_OVERFLOW");
    }

    function sub(
        uint96 a,
        uint96 b
        )
        internal
        pure
        returns (uint96 c)
    {

        require(b <= a, "SUB_UNDERFLOW");
        return a - b;
    }
}









library DepositTransaction
{

    using BytesUtil   for bytes;
    using MathUint96  for uint96;

    struct Deposit
    {
        address to;
        uint32  toAccountID;
        uint16  tokenID;
        uint96  amount;
    }

    function process(
        ExchangeData.State        storage S,
        ExchangeData.BlockContext memory  /*ctx*/,
        bytes                     memory  data,
        uint                              offset,
        bytes                     memory  /*auxiliaryData*/
        )
        internal
    {

        Deposit memory deposit = readTx(data, offset);
        if (deposit.amount == 0) {
            return;
        }

        ExchangeData.Deposit memory pendingDeposit = S.pendingDeposits[deposit.to][deposit.tokenID];
        require(pendingDeposit.timestamp > 0, "DEPOSIT_DOESNT_EXIST");


        require(pendingDeposit.amount >= deposit.amount, "INVALID_AMOUNT");
        pendingDeposit.amount = pendingDeposit.amount.sub(deposit.amount);

        if (pendingDeposit.amount == 0) {
            delete S.pendingDeposits[deposit.to][deposit.tokenID];
        } else {
            S.pendingDeposits[deposit.to][deposit.tokenID] = pendingDeposit;
        }
    }

    function readTx(
        bytes memory data,
        uint         offset
        )
        internal
        pure
        returns (Deposit memory deposit)
    {

        uint _offset = offset;
        deposit.to = data.toAddress(_offset);
        _offset += 20;
        deposit.toAccountID = data.toUint32(_offset);
        _offset += 4;
        deposit.tokenID = data.toUint16(_offset);
        _offset += 2;
        deposit.amount = data.toUint96(_offset);
        _offset += 12;
    }
}









library SignatureVerificationTransaction
{

    using BytesUtil            for bytes;
    using MathUint             for uint;

    struct SignatureVerification
    {
        address owner;
        uint32  accountID;
        uint256 data;
    }

    function readTx(
        bytes memory data,
        uint         offset
        )
        internal
        pure
        returns (SignatureVerification memory verification)
    {

        uint _offset = offset;
        verification.owner = data.toAddress(_offset);
        _offset += 20;
        verification.accountID = data.toUint32(_offset);
        _offset += 4;
        verification.data = data.toUint(_offset);
        _offset += 32;
    }
}





library SafeCast {


    function toUint128(uint256 value) internal pure returns (uint128) {

        require(value < 2**128, "SafeCast: value doesn\'t fit in 128 bits");
        return uint128(value);
    }

    function toUint96(uint256 value) internal pure returns (uint96) {

        require(value < 2**96, "SafeCast: value doesn\'t fit in 96 bits");
        return uint96(value);
    }

    function toUint64(uint256 value) internal pure returns (uint64) {

        require(value < 2**64, "SafeCast: value doesn\'t fit in 64 bits");
        return uint64(value);
    }

    function toUint32(uint256 value) internal pure returns (uint32) {

        require(value < 2**32, "SafeCast: value doesn\'t fit in 32 bits");
        return uint32(value);
    }

    function toUint40(uint256 value) internal pure returns (uint40) {

        require(value < 2**40, "SafeCast: value doesn\'t fit in 40 bits");
        return uint40(value);
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
}






library FloatUtil
{

    using MathUint for uint;
    using SafeCast for uint;

    function decodeFloat(
        uint f,
        uint numBits
        )
        internal
        pure
        returns (uint96 value)
    {

        uint numBitsMantissa = numBits.sub(5);
        uint exponent = f >> numBitsMantissa;
        require(exponent <= 77, "EXPONENT_TOO_LARGE");
        uint mantissa = f & ((1 << numBitsMantissa) - 1);
        value = mantissa.mul(10 ** exponent).toUint96();
    }
}










library TransferTransaction
{

    using BytesUtil            for bytes;
    using FloatUtil            for uint;
    using MathUint             for uint;
    using ExchangeSignatures   for ExchangeData.State;

    bytes32 constant public TRANSFER_TYPEHASH = keccak256(
        "Transfer(address from,address to,uint16 tokenID,uint96 amount,uint16 feeTokenID,uint96 maxFee,uint32 validUntil,uint32 storageID)"
    );

    struct Transfer
    {
        uint32  fromAccountID;
        uint32  toAccountID;
        address from;
        address to;
        uint16  tokenID;
        uint96  amount;
        uint16  feeTokenID;
        uint96  maxFee;
        uint96  fee;
        uint32  validUntil;
        uint32  storageID;
    }

    struct TransferAuxiliaryData
    {
        bytes  signature;
        uint96 maxFee;
        uint32 validUntil;
    }

    function process(
        ExchangeData.State        storage S,
        ExchangeData.BlockContext memory  ctx,
        bytes                     memory  data,
        uint                              offset,
        bytes                     memory  auxiliaryData
        )
        internal
    {

        Transfer memory transfer = readTx(data, offset);
        TransferAuxiliaryData memory auxData = abi.decode(auxiliaryData, (TransferAuxiliaryData));

        transfer.validUntil = auxData.validUntil;
        transfer.maxFee = auxData.maxFee == 0 ? transfer.fee : auxData.maxFee;
        require(ctx.timestamp < transfer.validUntil, "TRANSFER_EXPIRED");
        require(transfer.fee <= transfer.maxFee, "TRANSFER_FEE_TOO_HIGH");

        bytes32 txHash = hashTx(ctx.DOMAIN_SEPARATOR, transfer);

        S.requireAuthorizedTx(transfer.from, auxData.signature, txHash);
    }

    function readTx(
        bytes memory data,
        uint         offset
        )
        internal
        pure
        returns (Transfer memory transfer)
    {

        uint _offset = offset;
        require(data.toUint8(_offset) == 1, "INVALID_AUXILIARYDATA_DATA");
        _offset += 1;

        transfer.fromAccountID = data.toUint32(_offset);
        _offset += 4;
        transfer.toAccountID = data.toUint32(_offset);
        _offset += 4;
        transfer.tokenID = data.toUint16(_offset);
        _offset += 2;
        transfer.amount = uint(data.toUint24(_offset)).decodeFloat(24);
        _offset += 3;
        transfer.feeTokenID = data.toUint16(_offset);
        _offset += 2;
        transfer.fee = uint(data.toUint16(_offset)).decodeFloat(16);
        _offset += 2;
        transfer.storageID = data.toUint32(_offset);
        _offset += 4;
        transfer.to = data.toAddress(_offset);
        _offset += 20;
        transfer.from = data.toAddress(_offset);
        _offset += 20;
    }

    function hashTx(
        bytes32 DOMAIN_SEPARATOR,
        Transfer memory transfer
        )
        internal
        pure
        returns (bytes32)
    {

        return EIP712.hashPacked(
            DOMAIN_SEPARATOR,
            keccak256(
                abi.encode(
                    TRANSFER_TYPEHASH,
                    transfer.from,
                    transfer.to,
                    transfer.tokenID,
                    transfer.amount,
                    transfer.feeTokenID,
                    transfer.maxFee,
                    transfer.validUntil,
                    transfer.storageID
                )
            )
        );
    }
}






library ExchangeMode
{

    using MathUint  for uint;

    function isInWithdrawalMode(
        ExchangeData.State storage S
        )
        internal // inline call
        view
        returns (bool result)
    {

        result = S.withdrawalModeStartTime > 0;
    }

    function isShutdown(
        ExchangeData.State storage S
        )
        internal // inline call
        view
        returns (bool)
    {

        return S.shutdownModeStartTime > 0;
    }

    function getNumAvailableForcedSlots(
        ExchangeData.State storage S
        )
        internal
        view
        returns (uint)
    {

        return ExchangeData.MAX_OPEN_FORCED_REQUESTS() - S.numPendingForcedTransactions;
    }
}


library Poseidon
{


    struct HashInputs5
    {
        uint t0;
        uint t1;
        uint t2;
        uint t3;
        uint t4;
    }

    function hash_t5f6p52_internal(
        uint t0,
        uint t1,
        uint t2,
        uint t3,
        uint t4,
        uint q
        )
        internal
        pure
        returns (uint)
    {

        assembly {
            function mix(_t0, _t1, _t2, _t3, _t4, _q) -> nt0, nt1, nt2, nt3, nt4 {
                nt0 := mulmod(_t0, 4977258759536702998522229302103997878600602264560359702680165243908162277980, _q)
                nt0 := addmod(nt0, mulmod(_t1, 19167410339349846567561662441069598364702008768579734801591448511131028229281, _q), _q)
                nt0 := addmod(nt0, mulmod(_t2, 14183033936038168803360723133013092560869148726790180682363054735190196956789, _q), _q)
                nt0 := addmod(nt0, mulmod(_t3, 9067734253445064890734144122526450279189023719890032859456830213166173619761, _q), _q)
                nt0 := addmod(nt0, mulmod(_t4, 16378664841697311562845443097199265623838619398287411428110917414833007677155, _q), _q)
                nt1 := mulmod(_t0, 107933704346764130067829474107909495889716688591997879426350582457782826785, _q)
                nt1 := addmod(nt1, mulmod(_t1, 17034139127218860091985397764514160131253018178110701196935786874261236172431, _q), _q)
                nt1 := addmod(nt1, mulmod(_t2, 2799255644797227968811798608332314218966179365168250111693473252876996230317, _q), _q)
                nt1 := addmod(nt1, mulmod(_t3, 2482058150180648511543788012634934806465808146786082148795902594096349483974, _q), _q)
                nt1 := addmod(nt1, mulmod(_t4, 16563522740626180338295201738437974404892092704059676533096069531044355099628, _q), _q)
                nt2 := mulmod(_t0, 13596762909635538739079656925495736900379091964739248298531655823337482778123, _q)
                nt2 := addmod(nt2, mulmod(_t1, 18985203040268814769637347880759846911264240088034262814847924884273017355969, _q), _q)
                nt2 := addmod(nt2, mulmod(_t2, 8652975463545710606098548415650457376967119951977109072274595329619335974180, _q), _q)
                nt2 := addmod(nt2, mulmod(_t3, 970943815872417895015626519859542525373809485973005165410533315057253476903, _q), _q)
                nt2 := addmod(nt2, mulmod(_t4, 19406667490568134101658669326517700199745817783746545889094238643063688871948, _q), _q)
                nt3 := mulmod(_t0, 2953507793609469112222895633455544691298656192015062835263784675891831794974, _q)
                nt3 := addmod(nt3, mulmod(_t1, 19025623051770008118343718096455821045904242602531062247152770448380880817517, _q), _q)
                nt3 := addmod(nt3, mulmod(_t2, 9077319817220936628089890431129759976815127354480867310384708941479362824016, _q), _q)
                nt3 := addmod(nt3, mulmod(_t3, 4770370314098695913091200576539533727214143013236894216582648993741910829490, _q), _q)
                nt3 := addmod(nt3, mulmod(_t4, 4298564056297802123194408918029088169104276109138370115401819933600955259473, _q), _q)
                nt4 := mulmod(_t0, 8336710468787894148066071988103915091676109272951895469087957569358494947747, _q)
                nt4 := addmod(nt4, mulmod(_t1, 16205238342129310687768799056463408647672389183328001070715567975181364448609, _q), _q)
                nt4 := addmod(nt4, mulmod(_t2, 8303849270045876854140023508764676765932043944545416856530551331270859502246, _q), _q)
                nt4 := addmod(nt4, mulmod(_t3, 20218246699596954048529384569730026273241102596326201163062133863539137060414, _q), _q)
                nt4 := addmod(nt4, mulmod(_t4, 1712845821388089905746651754894206522004527237615042226559791118162382909269, _q), _q)
            }

            function ark(_t0, _t1, _t2, _t3, _t4, _q, c) -> nt0, nt1, nt2, nt3, nt4 {
                nt0 := addmod(_t0, c, _q)
                nt1 := addmod(_t1, c, _q)
                nt2 := addmod(_t2, c, _q)
                nt3 := addmod(_t3, c, _q)
                nt4 := addmod(_t4, c, _q)
            }

            function sbox_full(_t0, _t1, _t2, _t3, _t4, _q) -> nt0, nt1, nt2, nt3, nt4 {
                nt0 := mulmod(_t0, _t0, _q)
                nt0 := mulmod(nt0, nt0, _q)
                nt0 := mulmod(_t0, nt0, _q)
                nt1 := mulmod(_t1, _t1, _q)
                nt1 := mulmod(nt1, nt1, _q)
                nt1 := mulmod(_t1, nt1, _q)
                nt2 := mulmod(_t2, _t2, _q)
                nt2 := mulmod(nt2, nt2, _q)
                nt2 := mulmod(_t2, nt2, _q)
                nt3 := mulmod(_t3, _t3, _q)
                nt3 := mulmod(nt3, nt3, _q)
                nt3 := mulmod(_t3, nt3, _q)
                nt4 := mulmod(_t4, _t4, _q)
                nt4 := mulmod(nt4, nt4, _q)
                nt4 := mulmod(_t4, nt4, _q)
            }

            function sbox_partial(_t, _q) -> nt {
                nt := mulmod(_t, _t, _q)
                nt := mulmod(nt, nt, _q)
                nt := mulmod(_t, nt, _q)
            }

            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 14397397413755236225575615486459253198602422701513067526754101844196324375522)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 10405129301473404666785234951972711717481302463898292859783056520670200613128)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 5179144822360023508491245509308555580251733042407187134628755730783052214509)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 9132640374240188374542843306219594180154739721841249568925550236430986592615)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20360807315276763881209958738450444293273549928693737723235350358403012458514)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 17933600965499023212689924809448543050840131883187652471064418452962948061619)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 3636213416533737411392076250708419981662897009810345015164671602334517041153)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 2008540005368330234524962342006691994500273283000229509835662097352946198608)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 16018407964853379535338740313053768402596521780991140819786560130595652651567)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20653139667070586705378398435856186172195806027708437373983929336015162186471)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 17887713874711369695406927657694993484804203950786446055999405564652412116765)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 4852706232225925756777361208698488277369799648067343227630786518486608711772)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 8969172011633935669771678412400911310465619639756845342775631896478908389850)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20570199545627577691240476121888846460936245025392381957866134167601058684375)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 16442329894745639881165035015179028112772410105963688121820543219662832524136)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20060625627350485876280451423010593928172611031611836167979515653463693899374)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 16637282689940520290130302519163090147511023430395200895953984829546679599107)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 15599196921909732993082127725908821049411366914683565306060493533569088698214)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 16894591341213863947423904025624185991098788054337051624251730868231322135455)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 1197934381747032348421303489683932612752526046745577259575778515005162320212)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 6172482022646932735745595886795230725225293469762393889050804649558459236626)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 21004037394166516054140386756510609698837211370585899203851827276330669555417)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 15262034989144652068456967541137853724140836132717012646544737680069032573006)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 15017690682054366744270630371095785995296470601172793770224691982518041139766)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 15159744167842240513848638419303545693472533086570469712794583342699782519832)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 11178069035565459212220861899558526502477231302924961773582350246646450941231)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 21154888769130549957415912997229564077486639529994598560737238811887296922114)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20162517328110570500010831422938033120419484532231241180224283481905744633719)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 2777362604871784250419758188173029886707024739806641263170345377816177052018)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 15732290486829619144634131656503993123618032247178179298922551820261215487562)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 6024433414579583476444635447152826813568595303270846875177844482142230009826)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 17677827682004946431939402157761289497221048154630238117709539216286149983245)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 10716307389353583413755237303156291454109852751296156900963208377067748518748)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 14925386988604173087143546225719076187055229908444910452781922028996524347508)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 8940878636401797005293482068100797531020505636124892198091491586778667442523)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 18911747154199663060505302806894425160044925686870165583944475880789706164410)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 8821532432394939099312235292271438180996556457308429936910969094255825456935)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 20632576502437623790366878538516326728436616723089049415538037018093616927643)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 71447649211767888770311304010816315780740050029903404046389165015534756512)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 2781996465394730190470582631099299305677291329609718650018200531245670229393)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 12441376330954323535872906380510501637773629931719508864016287320488688345525)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 2558302139544901035700544058046419714227464650146159803703499681139469546006)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 10087036781939179132584550273563255199577525914374285705149349445480649057058)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 4267692623754666261749551533667592242661271409704769363166965280715887854739)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 4945579503584457514844595640661884835097077318604083061152997449742124905548)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 17742335354489274412669987990603079185096280484072783973732137326144230832311)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 6266270088302506215402996795500854910256503071464802875821837403486057988208)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 2716062168542520412498610856550519519760063668165561277991771577403400784706)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 19118392018538203167410421493487769944462015419023083813301166096764262134232)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 9386595745626044000666050847309903206827901310677406022353307960932745699524)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 9121640807890366356465620448383131419933298563527245687958865317869840082266)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 3078975275808111706229899605611544294904276390490742680006005661017864583210)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 7157404299437167354719786626667769956233708887934477609633504801472827442743)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 14056248655941725362944552761799461694550787028230120190862133165195793034373)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 14124396743304355958915937804966111851843703158171757752158388556919187839849)
            t0 := sbox_partial(t0, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 11851254356749068692552943732920045260402277343008629727465773766468466181076)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 9799099446406796696742256539758943483211846559715874347178722060519817626047)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := ark(t0, t1, t2, t3, t4, q, 10156146186214948683880719664738535455146137901666656566575307300522957959544)
            t0, t1, t2, t3, t4 := sbox_full(t0, t1, t2, t3, t4, q)
            t0, t1, t2, t3, t4 := mix(t0, t1, t2, t3, t4, q)
        }
        return t0;
    }

    function hash_t5f6p52(HashInputs5 memory i, uint q) internal pure returns (uint)
    {

        require(i.t0 < q, "INVALID_INPUT");
        require(i.t1 < q, "INVALID_INPUT");
        require(i.t2 < q, "INVALID_INPUT");
        require(i.t3 < q, "INVALID_INPUT");
        require(i.t4 < q, "INVALID_INPUT");

        return hash_t5f6p52_internal(i.t0, i.t1, i.t2, i.t3, i.t4, q);
    }



    struct HashInputs7
    {
        uint t0;
        uint t1;
        uint t2;
        uint t3;
        uint t4;
        uint t5;
        uint t6;
    }

    function mix(HashInputs7 memory i, uint q) internal pure
    {

        HashInputs7 memory o;
        o.t0 = mulmod(i.t0, 14183033936038168803360723133013092560869148726790180682363054735190196956789, q);
        o.t0 = addmod(o.t0, mulmod(i.t1, 9067734253445064890734144122526450279189023719890032859456830213166173619761, q), q);
        o.t0 = addmod(o.t0, mulmod(i.t2, 16378664841697311562845443097199265623838619398287411428110917414833007677155, q), q);
        o.t0 = addmod(o.t0, mulmod(i.t3, 12968540216479938138647596899147650021419273189336843725176422194136033835172, q), q);
        o.t0 = addmod(o.t0, mulmod(i.t4, 3636162562566338420490575570584278737093584021456168183289112789616069756675, q), q);
        o.t0 = addmod(o.t0, mulmod(i.t5, 8949952361235797771659501126471156178804092479420606597426318793013844305422, q), q);
        o.t0 = addmod(o.t0, mulmod(i.t6, 13586657904816433080148729258697725609063090799921401830545410130405357110367, q), q);
        o.t1 = mulmod(i.t0, 2799255644797227968811798608332314218966179365168250111693473252876996230317, q);
        o.t1 = addmod(o.t1, mulmod(i.t1, 2482058150180648511543788012634934806465808146786082148795902594096349483974, q), q);
        o.t1 = addmod(o.t1, mulmod(i.t2, 16563522740626180338295201738437974404892092704059676533096069531044355099628, q), q);
        o.t1 = addmod(o.t1, mulmod(i.t3, 10468644849657689537028565510142839489302836569811003546969773105463051947124, q), q);
        o.t1 = addmod(o.t1, mulmod(i.t4, 3328913364598498171733622353010907641674136720305714432354138807013088636408, q), q);
        o.t1 = addmod(o.t1, mulmod(i.t5, 8642889650254799419576843603477253661899356105675006557919250564400804756641, q), q);
        o.t1 = addmod(o.t1, mulmod(i.t6, 14300697791556510113764686242794463641010174685800128469053974698256194076125, q), q);
        o.t2 = mulmod(i.t0, 8652975463545710606098548415650457376967119951977109072274595329619335974180, q);
        o.t2 = addmod(o.t2, mulmod(i.t1, 970943815872417895015626519859542525373809485973005165410533315057253476903, q), q);
        o.t2 = addmod(o.t2, mulmod(i.t2, 19406667490568134101658669326517700199745817783746545889094238643063688871948, q), q);
        o.t2 = addmod(o.t2, mulmod(i.t3, 17049854690034965250221386317058877242629221002521630573756355118745574274967, q), q);
        o.t2 = addmod(o.t2, mulmod(i.t4, 4964394613021008685803675656098849539153699842663541444414978877928878266244, q), q);
        o.t2 = addmod(o.t2, mulmod(i.t5, 15474947305445649466370538888925567099067120578851553103424183520405650587995, q), q);
        o.t2 = addmod(o.t2, mulmod(i.t6, 1016119095639665978105768933448186152078842964810837543326777554729232767846, q), q);
        o.t3 = mulmod(i.t0, 9077319817220936628089890431129759976815127354480867310384708941479362824016, q);
        o.t3 = addmod(o.t3, mulmod(i.t1, 4770370314098695913091200576539533727214143013236894216582648993741910829490, q), q);
        o.t3 = addmod(o.t3, mulmod(i.t2, 4298564056297802123194408918029088169104276109138370115401819933600955259473, q), q);
        o.t3 = addmod(o.t3, mulmod(i.t3, 6905514380186323693285869145872115273350947784558995755916362330070690839131, q), q);
        o.t3 = addmod(o.t3, mulmod(i.t4, 4783343257810358393326889022942241108539824540285247795235499223017138301952, q), q);
        o.t3 = addmod(o.t3, mulmod(i.t5, 1420772902128122367335354247676760257656541121773854204774788519230732373317, q), q);
        o.t3 = addmod(o.t3, mulmod(i.t6, 14172871439045259377975734198064051992755748777535789572469924335100006948373, q), q);
        o.t4 = mulmod(i.t0, 8303849270045876854140023508764676765932043944545416856530551331270859502246, q);
        o.t4 = addmod(o.t4, mulmod(i.t1, 20218246699596954048529384569730026273241102596326201163062133863539137060414, q), q);
        o.t4 = addmod(o.t4, mulmod(i.t2, 1712845821388089905746651754894206522004527237615042226559791118162382909269, q), q);
        o.t4 = addmod(o.t4, mulmod(i.t3, 13001155522144542028910638547179410124467185319212645031214919884423841839406, q), q);
        o.t4 = addmod(o.t4, mulmod(i.t4, 16037892369576300958623292723740289861626299352695838577330319504984091062115, q), q);
        o.t4 = addmod(o.t4, mulmod(i.t5, 19189494548480259335554606182055502469831573298885662881571444557262020106898, q), q);
        o.t4 = addmod(o.t4, mulmod(i.t6, 19032687447778391106390582750185144485341165205399984747451318330476859342654, q), q);
        o.t5 = mulmod(i.t0, 13272957914179340594010910867091459756043436017766464331915862093201960540910, q);
        o.t5 = addmod(o.t5, mulmod(i.t1, 9416416589114508529880440146952102328470363729880726115521103179442988482948, q), q);
        o.t5 = addmod(o.t5, mulmod(i.t2, 8035240799672199706102747147502951589635001418759394863664434079699838251138, q), q);
        o.t5 = addmod(o.t5, mulmod(i.t3, 21642389080762222565487157652540372010968704000567605990102641816691459811717, q), q);
        o.t5 = addmod(o.t5, mulmod(i.t4, 20261355950827657195644012399234591122288573679402601053407151083849785332516, q), q);
        o.t5 = addmod(o.t5, mulmod(i.t5, 14514189384576734449268559374569145463190040567900950075547616936149781403109, q), q);
        o.t5 = addmod(o.t5, mulmod(i.t6, 19038036134886073991945204537416211699632292792787812530208911676638479944765, q), q);
        o.t6 = mulmod(i.t0, 15627836782263662543041758927100784213807648787083018234961118439434298020664, q);
        o.t6 = addmod(o.t6, mulmod(i.t1, 5655785191024506056588710805596292231240948371113351452712848652644610823632, q), q);
        o.t6 = addmod(o.t6, mulmod(i.t2, 8265264721707292643644260517162050867559314081394556886644673791575065394002, q), q);
        o.t6 = addmod(o.t6, mulmod(i.t3, 17151144681903609082202835646026478898625761142991787335302962548605510241586, q), q);
        o.t6 = addmod(o.t6, mulmod(i.t4, 18731644709777529787185361516475509623264209648904603914668024590231177708831, q), q);
        o.t6 = addmod(o.t6, mulmod(i.t5, 20697789991623248954020701081488146717484139720322034504511115160686216223641, q), q);
        o.t6 = addmod(o.t6, mulmod(i.t6, 6200020095464686209289974437830528853749866001482481427982839122465470640886, q), q);
        i.t0 = o.t0;
        i.t1 = o.t1;
        i.t2 = o.t2;
        i.t3 = o.t3;
        i.t4 = o.t4;
        i.t5 = o.t5;
        i.t6 = o.t6;
    }

    function ark(HashInputs7 memory i, uint q, uint c) internal pure
    {

        HashInputs7 memory o;
        o.t0 = addmod(i.t0, c, q);
        o.t1 = addmod(i.t1, c, q);
        o.t2 = addmod(i.t2, c, q);
        o.t3 = addmod(i.t3, c, q);
        o.t4 = addmod(i.t4, c, q);
        o.t5 = addmod(i.t5, c, q);
        o.t6 = addmod(i.t6, c, q);
        i.t0 = o.t0;
        i.t1 = o.t1;
        i.t2 = o.t2;
        i.t3 = o.t3;
        i.t4 = o.t4;
        i.t5 = o.t5;
        i.t6 = o.t6;
    }

    function sbox_full(HashInputs7 memory i, uint q) internal pure
    {

        HashInputs7 memory o;
        o.t0 = mulmod(i.t0, i.t0, q);
        o.t0 = mulmod(o.t0, o.t0, q);
        o.t0 = mulmod(i.t0, o.t0, q);
        o.t1 = mulmod(i.t1, i.t1, q);
        o.t1 = mulmod(o.t1, o.t1, q);
        o.t1 = mulmod(i.t1, o.t1, q);
        o.t2 = mulmod(i.t2, i.t2, q);
        o.t2 = mulmod(o.t2, o.t2, q);
        o.t2 = mulmod(i.t2, o.t2, q);
        o.t3 = mulmod(i.t3, i.t3, q);
        o.t3 = mulmod(o.t3, o.t3, q);
        o.t3 = mulmod(i.t3, o.t3, q);
        o.t4 = mulmod(i.t4, i.t4, q);
        o.t4 = mulmod(o.t4, o.t4, q);
        o.t4 = mulmod(i.t4, o.t4, q);
        o.t5 = mulmod(i.t5, i.t5, q);
        o.t5 = mulmod(o.t5, o.t5, q);
        o.t5 = mulmod(i.t5, o.t5, q);
        o.t6 = mulmod(i.t6, i.t6, q);
        o.t6 = mulmod(o.t6, o.t6, q);
        o.t6 = mulmod(i.t6, o.t6, q);
        i.t0 = o.t0;
        i.t1 = o.t1;
        i.t2 = o.t2;
        i.t3 = o.t3;
        i.t4 = o.t4;
        i.t5 = o.t5;
        i.t6 = o.t6;
    }

    function sbox_partial(HashInputs7 memory i, uint q) internal pure
    {

        HashInputs7 memory o;
        o.t0 = mulmod(i.t0, i.t0, q);
        o.t0 = mulmod(o.t0, o.t0, q);
        o.t0 = mulmod(i.t0, o.t0, q);
        i.t0 = o.t0;
    }

    function hash_t7f6p52(HashInputs7 memory i, uint q) internal pure returns (uint)
    {

        require(i.t0 < q, "INVALID_INPUT");
        require(i.t1 < q, "INVALID_INPUT");
        require(i.t2 < q, "INVALID_INPUT");
        require(i.t3 < q, "INVALID_INPUT");
        require(i.t4 < q, "INVALID_INPUT");
        require(i.t5 < q, "INVALID_INPUT");
        require(i.t6 < q, "INVALID_INPUT");

        ark(i, q, 14397397413755236225575615486459253198602422701513067526754101844196324375522);
        sbox_full(i, q);
        mix(i, q);
        ark(i, q, 10405129301473404666785234951972711717481302463898292859783056520670200613128);
        sbox_full(i, q);
        mix(i, q);
        ark(i, q, 5179144822360023508491245509308555580251733042407187134628755730783052214509);
        sbox_full(i, q);
        mix(i, q);
        ark(i, q, 9132640374240188374542843306219594180154739721841249568925550236430986592615);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20360807315276763881209958738450444293273549928693737723235350358403012458514);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 17933600965499023212689924809448543050840131883187652471064418452962948061619);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 3636213416533737411392076250708419981662897009810345015164671602334517041153);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 2008540005368330234524962342006691994500273283000229509835662097352946198608);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 16018407964853379535338740313053768402596521780991140819786560130595652651567);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20653139667070586705378398435856186172195806027708437373983929336015162186471);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 17887713874711369695406927657694993484804203950786446055999405564652412116765);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 4852706232225925756777361208698488277369799648067343227630786518486608711772);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 8969172011633935669771678412400911310465619639756845342775631896478908389850);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20570199545627577691240476121888846460936245025392381957866134167601058684375);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 16442329894745639881165035015179028112772410105963688121820543219662832524136);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20060625627350485876280451423010593928172611031611836167979515653463693899374);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 16637282689940520290130302519163090147511023430395200895953984829546679599107);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 15599196921909732993082127725908821049411366914683565306060493533569088698214);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 16894591341213863947423904025624185991098788054337051624251730868231322135455);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 1197934381747032348421303489683932612752526046745577259575778515005162320212);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 6172482022646932735745595886795230725225293469762393889050804649558459236626);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 21004037394166516054140386756510609698837211370585899203851827276330669555417);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 15262034989144652068456967541137853724140836132717012646544737680069032573006);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 15017690682054366744270630371095785995296470601172793770224691982518041139766);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 15159744167842240513848638419303545693472533086570469712794583342699782519832);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 11178069035565459212220861899558526502477231302924961773582350246646450941231);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 21154888769130549957415912997229564077486639529994598560737238811887296922114);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20162517328110570500010831422938033120419484532231241180224283481905744633719);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 2777362604871784250419758188173029886707024739806641263170345377816177052018);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 15732290486829619144634131656503993123618032247178179298922551820261215487562);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 6024433414579583476444635447152826813568595303270846875177844482142230009826);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 17677827682004946431939402157761289497221048154630238117709539216286149983245);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 10716307389353583413755237303156291454109852751296156900963208377067748518748);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 14925386988604173087143546225719076187055229908444910452781922028996524347508);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 8940878636401797005293482068100797531020505636124892198091491586778667442523);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 18911747154199663060505302806894425160044925686870165583944475880789706164410);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 8821532432394939099312235292271438180996556457308429936910969094255825456935);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 20632576502437623790366878538516326728436616723089049415538037018093616927643);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 71447649211767888770311304010816315780740050029903404046389165015534756512);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 2781996465394730190470582631099299305677291329609718650018200531245670229393);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 12441376330954323535872906380510501637773629931719508864016287320488688345525);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 2558302139544901035700544058046419714227464650146159803703499681139469546006);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 10087036781939179132584550273563255199577525914374285705149349445480649057058);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 4267692623754666261749551533667592242661271409704769363166965280715887854739);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 4945579503584457514844595640661884835097077318604083061152997449742124905548);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 17742335354489274412669987990603079185096280484072783973732137326144230832311);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 6266270088302506215402996795500854910256503071464802875821837403486057988208);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 2716062168542520412498610856550519519760063668165561277991771577403400784706);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 19118392018538203167410421493487769944462015419023083813301166096764262134232);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 9386595745626044000666050847309903206827901310677406022353307960932745699524);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 9121640807890366356465620448383131419933298563527245687958865317869840082266);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 3078975275808111706229899605611544294904276390490742680006005661017864583210);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 7157404299437167354719786626667769956233708887934477609633504801472827442743);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 14056248655941725362944552761799461694550787028230120190862133165195793034373);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 14124396743304355958915937804966111851843703158171757752158388556919187839849);
        sbox_partial(i, q);
        mix(i, q);
        ark(i, q, 11851254356749068692552943732920045260402277343008629727465773766468466181076);
        sbox_full(i, q);
        mix(i, q);
        ark(i, q, 9799099446406796696742256539758943483211846559715874347178722060519817626047);
        sbox_full(i, q);
        mix(i, q);
        ark(i, q, 10156146186214948683880719664738535455146137901666656566575307300522957959544);
        sbox_full(i, q);
        mix(i, q);

        return i.t0;
    }
}







library ExchangeBalances
{

    using MathUint  for uint;

    function verifyAccountBalance(
        uint                              merkleRoot,
        ExchangeData.MerkleProof calldata merkleProof
        )
        public
        pure
    {

        require(
            isAccountBalanceCorrect(merkleRoot, merkleProof),
            "INVALID_MERKLE_TREE_DATA"
        );
    }

    function isAccountBalanceCorrect(
        uint                            merkleRoot,
        ExchangeData.MerkleProof memory merkleProof
        )
        public
        pure
        returns (bool)
    {

        uint calculatedRoot = getBalancesRoot(
            merkleProof.balanceLeaf.tokenID,
            merkleProof.balanceLeaf.balance,
            merkleProof.balanceLeaf.weightAMM,
            merkleProof.balanceLeaf.storageRoot,
            merkleProof.balanceMerkleProof
        );
        calculatedRoot = getAccountInternalsRoot(
            merkleProof.accountLeaf.accountID,
            merkleProof.accountLeaf.owner,
            merkleProof.accountLeaf.pubKeyX,
            merkleProof.accountLeaf.pubKeyY,
            merkleProof.accountLeaf.nonce,
            merkleProof.accountLeaf.feeBipsAMM,
            calculatedRoot,
            merkleProof.accountMerkleProof
        );
        return (calculatedRoot == merkleRoot);
    }

    function getBalancesRoot(
        uint16   tokenID,
        uint     balance,
        uint     weightAMM,
        uint     storageRoot,
        uint[24] memory balanceMerkleProof
        )
        private
        pure
        returns (uint)
    {

        uint balanceItem = hashImpl(balance, weightAMM, storageRoot, 0);
        uint _id = tokenID;
        for (uint depth = 0; depth < 8; depth++) {
            uint base = depth * 3;
            if (_id & 3 == 0) {
                balanceItem = hashImpl(
                    balanceItem,
                    balanceMerkleProof[base],
                    balanceMerkleProof[base + 1],
                    balanceMerkleProof[base + 2]
                );
            } else if (_id & 3 == 1) {
                balanceItem = hashImpl(
                    balanceMerkleProof[base],
                    balanceItem,
                    balanceMerkleProof[base + 1],
                    balanceMerkleProof[base + 2]
                );
            } else if (_id & 3 == 2) {
                balanceItem = hashImpl(
                    balanceMerkleProof[base],
                    balanceMerkleProof[base + 1],
                    balanceItem,
                    balanceMerkleProof[base + 2]
                );
            } else if (_id & 3 == 3) {
                balanceItem = hashImpl(
                    balanceMerkleProof[base],
                    balanceMerkleProof[base + 1],
                    balanceMerkleProof[base + 2],
                    balanceItem
                );
            }
            _id = _id >> 2;
        }
        return balanceItem;
    }

    function getAccountInternalsRoot(
        uint32   accountID,
        address  owner,
        uint     pubKeyX,
        uint     pubKeyY,
        uint     nonce,
        uint     feeBipsAMM,
        uint     balancesRoot,
        uint[48] memory accountMerkleProof
        )
        private
        pure
        returns (uint)
    {

        uint accountItem = hashAccountLeaf(uint(owner), pubKeyX, pubKeyY, nonce, feeBipsAMM, balancesRoot);
        uint _id = accountID;
        for (uint depth = 0; depth < 16; depth++) {
            uint base = depth * 3;
            if (_id & 3 == 0) {
                accountItem = hashImpl(
                    accountItem,
                    accountMerkleProof[base],
                    accountMerkleProof[base + 1],
                    accountMerkleProof[base + 2]
                );
            } else if (_id & 3 == 1) {
                accountItem = hashImpl(
                    accountMerkleProof[base],
                    accountItem,
                    accountMerkleProof[base + 1],
                    accountMerkleProof[base + 2]
                );
            } else if (_id & 3 == 2) {
                accountItem = hashImpl(
                    accountMerkleProof[base],
                    accountMerkleProof[base + 1],
                    accountItem,
                    accountMerkleProof[base + 2]
                );
            } else if (_id & 3 == 3) {
                accountItem = hashImpl(
                    accountMerkleProof[base],
                    accountMerkleProof[base + 1],
                    accountMerkleProof[base + 2],
                    accountItem
                );
            }
            _id = _id >> 2;
        }
        return accountItem;
    }

    function hashAccountLeaf(
        uint t0,
        uint t1,
        uint t2,
        uint t3,
        uint t4,
        uint t5
        )
        public
        pure
        returns (uint)
    {

        Poseidon.HashInputs7 memory inputs = Poseidon.HashInputs7(t0, t1, t2, t3, t4, t5, 0);
        return Poseidon.hash_t7f6p52(inputs, ExchangeData.SNARK_SCALAR_FIELD());
    }

    function hashImpl(
        uint t0,
        uint t1,
        uint t2,
        uint t3
        )
        private
        pure
        returns (uint)
    {

        Poseidon.HashInputs5 memory inputs = Poseidon.HashInputs5(t0, t1, t2, t3, 0);
        return Poseidon.hash_t5f6p52(inputs, ExchangeData.SNARK_SCALAR_FIELD());
    }
}




library ERC20SafeTransfer
{

    function safeTransferAndVerify(
        address token,
        address to,
        uint    value
        )
        internal
    {

        safeTransferWithGasLimitAndVerify(
            token,
            to,
            value,
            gasleft()
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint    value
        )
        internal
        returns (bool)
    {

        return safeTransferWithGasLimit(
            token,
            to,
            value,
            gasleft()
        );
    }

    function safeTransferWithGasLimitAndVerify(
        address token,
        address to,
        uint    value,
        uint    gasLimit
        )
        internal
    {

        require(
            safeTransferWithGasLimit(token, to, value, gasLimit),
            "TRANSFER_FAILURE"
        );
    }

    function safeTransferWithGasLimit(
        address token,
        address to,
        uint    value,
        uint    gasLimit
        )
        internal
        returns (bool)
    {


        bytes memory callData = abi.encodeWithSelector(
            bytes4(0xa9059cbb),
            to,
            value
        );
        (bool success, ) = token.call{gas: gasLimit}(callData);
        return checkReturnValue(success);
    }

    function safeTransferFromAndVerify(
        address token,
        address from,
        address to,
        uint    value
        )
        internal
    {

        safeTransferFromWithGasLimitAndVerify(
            token,
            from,
            to,
            value,
            gasleft()
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint    value
        )
        internal
        returns (bool)
    {

        return safeTransferFromWithGasLimit(
            token,
            from,
            to,
            value,
            gasleft()
        );
    }

    function safeTransferFromWithGasLimitAndVerify(
        address token,
        address from,
        address to,
        uint    value,
        uint    gasLimit
        )
        internal
    {

        bool result = safeTransferFromWithGasLimit(
            token,
            from,
            to,
            value,
            gasLimit
        );
        require(result, "TRANSFER_FAILURE");
    }

    function safeTransferFromWithGasLimit(
        address token,
        address from,
        address to,
        uint    value,
        uint    gasLimit
        )
        internal
        returns (bool)
    {


        bytes memory callData = abi.encodeWithSelector(
            bytes4(0x23b872dd),
            from,
            to,
            value
        );
        (bool success, ) = token.call{gas: gasLimit}(callData);
        return checkReturnValue(success);
    }

    function checkReturnValue(
        bool success
        )
        internal
        pure
        returns (bool)
    {

        if (success) {
            assembly {
                switch returndatasize()
                case 0 {
                    success := 1
                }
                case 32 {
                    returndatacopy(0, 0, 32)
                    success := mload(0)
                }
                default {
                    success := 0
                }
            }
        }
        return success;
    }
}








library ExchangeTokens
{

    using MathUint          for uint;
    using ERC20SafeTransfer for address;
    using ExchangeMode      for ExchangeData.State;

    event TokenRegistered(
        address token,
        uint16  tokenId
    );

    function getTokenAddress(
        ExchangeData.State storage S,
        uint16 tokenID
        )
        public
        view
        returns (address)
    {

        require(tokenID < S.tokens.length, "INVALID_TOKEN_ID");
        return S.tokens[tokenID].token;
    }

    function registerToken(
        ExchangeData.State storage S,
        address tokenAddress
        )
        public
        returns (uint16 tokenID)
    {

        require(!S.isInWithdrawalMode(), "INVALID_MODE");
        require(S.tokenToTokenId[tokenAddress] == 0, "TOKEN_ALREADY_EXIST");
        require(S.tokens.length < ExchangeData.MAX_NUM_TOKENS(), "TOKEN_REGISTRY_FULL");

        if (S.depositContract != IDepositContract(0)) {
            require(
                S.depositContract.isTokenSupported(tokenAddress),
                "UNSUPPORTED_TOKEN"
            );
        }

        ExchangeData.Token memory token = ExchangeData.Token(
            tokenAddress
        );
        tokenID = uint16(S.tokens.length);
        S.tokens.push(token);
        S.tokenToTokenId[tokenAddress] = tokenID + 1;

        emit TokenRegistered(tokenAddress, tokenID);
    }

    function getTokenID(
        ExchangeData.State storage S,
        address tokenAddress
        )
        internal  // inline call
        view
        returns (uint16 tokenID)
    {

        tokenID = S.tokenToTokenId[tokenAddress];
        require(tokenID != 0, "TOKEN_NOT_FOUND");
        tokenID = tokenID - 1;
    }
}










library ExchangeWithdrawals
{

    enum WithdrawalCategory
    {
        DISTRIBUTION,
        FROM_MERKLE_TREE,
        FROM_DEPOSIT_REQUEST,
        FROM_APPROVED_WITHDRAWAL
    }

    using AddressUtil       for address;
    using AddressUtil       for address payable;
    using BytesUtil         for bytes;
    using MathUint          for uint;
    using ExchangeBalances  for ExchangeData.State;
    using ExchangeMode      for ExchangeData.State;
    using ExchangeTokens    for ExchangeData.State;

    event ForcedWithdrawalRequested(
        address owner,
        address token,
        uint32  accountID
    );

    event WithdrawalCompleted(
        uint8   category,
        address from,
        address to,
        address token,
        uint    amount
    );

    event WithdrawalFailed(
        uint8   category,
        address from,
        address to,
        address token,
        uint    amount
    );

    function forceWithdraw(
        ExchangeData.State storage S,
        address owner,
        address token,
        uint32  accountID
        )
        public
    {

        require(!S.isInWithdrawalMode(), "INVALID_MODE");
        require(S.getNumAvailableForcedSlots() > 0, "TOO_MANY_REQUESTS_OPEN");
        require(accountID < ExchangeData.MAX_NUM_ACCOUNTS(), "INVALID_ACCOUNTID");

        uint16 tokenID = S.getTokenID(token);

        uint withdrawalFeeETH = S.loopring.forcedWithdrawalFee();

        require(msg.value >= withdrawalFeeETH, "INSUFFICIENT_FEE");

        uint feeSurplus = msg.value.sub(withdrawalFeeETH);
        if (feeSurplus > 0) {
            msg.sender.sendETHAndVerify(feeSurplus, gasleft());
        }

        require(
            S.pendingForcedWithdrawals[accountID][tokenID].timestamp == 0,
            "WITHDRAWAL_ALREADY_PENDING"
        );

        S.pendingForcedWithdrawals[accountID][tokenID] = ExchangeData.ForcedWithdrawal({
            owner: owner,
            timestamp: uint64(block.timestamp)
        });

        S.numPendingForcedTransactions++;

        emit ForcedWithdrawalRequested(
            owner,
            token,
            accountID
        );
    }

    function withdrawFromMerkleTree(
        ExchangeData.State       storage S,
        ExchangeData.MerkleProof calldata merkleProof
        )
        public
    {

        require(S.isInWithdrawalMode(), "NOT_IN_WITHDRAW_MODE");

        address owner = merkleProof.accountLeaf.owner;
        uint32 accountID = merkleProof.accountLeaf.accountID;
        uint16 tokenID = merkleProof.balanceLeaf.tokenID;
        uint96 balance = merkleProof.balanceLeaf.balance;

        require(S.withdrawnInWithdrawMode[accountID][tokenID] == false, "WITHDRAWN_ALREADY");

        ExchangeBalances.verifyAccountBalance(
            uint(S.merkleRoot),
            merkleProof
        );

        S.withdrawnInWithdrawMode[accountID][tokenID] = true;

        transferTokens(
            S,
            uint8(WithdrawalCategory.FROM_MERKLE_TREE),
            owner,
            owner,
            tokenID,
            balance,
            new bytes(0),
            gasleft(),
            false
        );
    }

    function withdrawFromDepositRequest(
        ExchangeData.State storage S,
        address owner,
        address token
        )
        public
    {

        uint16 tokenID = S.getTokenID(token);
        ExchangeData.Deposit storage deposit = S.pendingDeposits[owner][tokenID];
        require(deposit.timestamp != 0, "DEPOSIT_NOT_WITHDRAWABLE_YET");

        require(
            block.timestamp >= deposit.timestamp + S.maxAgeDepositUntilWithdrawable ||
            S.isInWithdrawalMode(),
            "DEPOSIT_NOT_WITHDRAWABLE_YET"
        );

        uint amount = deposit.amount;

        delete S.pendingDeposits[owner][tokenID];

        transferTokens(
            S,
            uint8(WithdrawalCategory.FROM_DEPOSIT_REQUEST),
            owner,
            owner,
            tokenID,
            amount,
            new bytes(0),
            gasleft(),
            false
        );
    }

    function withdrawFromApprovedWithdrawals(
        ExchangeData.State storage S,
        address[] memory owners,
        address[] memory tokens
        )
        public
    {

        require(owners.length == tokens.length, "INVALID_INPUT_DATA");
        for (uint i = 0; i < owners.length; i++) {
            address owner = owners[i];
            uint16 tokenID = S.getTokenID(tokens[i]);
            uint amount = S.amountWithdrawable[owner][tokenID];

            delete S.amountWithdrawable[owner][tokenID];

            transferTokens(
                S,
                uint8(WithdrawalCategory.FROM_APPROVED_WITHDRAWAL),
                owner,
                owner,
                tokenID,
                amount,
                new bytes(0),
                gasleft(),
                false
            );
        }
    }

    function distributeWithdrawal(
        ExchangeData.State storage S,
        address from,
        address to,
        uint16  tokenID,
        uint    amount,
        bytes   memory extraData,
        uint    gasLimit
        )
        public
    {

        bool success = transferTokens(
            S,
            uint8(WithdrawalCategory.DISTRIBUTION),
            from,
            to,
            tokenID,
            amount,
            extraData,
            gasLimit,
            true
        );
        if (!success) {
            S.amountWithdrawable[to][tokenID] = S.amountWithdrawable[to][tokenID].add(amount);
        }
    }


    function transferTokens(
        ExchangeData.State storage S,
        uint8   category,
        address from,
        address to,
        uint16  tokenID,
        uint    amount,
        bytes   memory extraData,
        uint    gasLimit,
        bool    allowFailure
        )
        private
        returns (bool success)
    {

        if (to == address(0)) {
            to = S.loopring.protocolFeeVault();
        }
        address token = S.getTokenAddress(tokenID);

        if (gasLimit > 0) {
            try S.depositContract.withdraw{gas: gasLimit}(from, to, token, amount, extraData) {
                success = true;
            } catch {
                success = false;
            }
        } else {
            success = false;
        }

        require(allowFailure || success, "TRANSFER_FAILURE");

        if (success) {
            emit WithdrawalCompleted(category, from, to, token, amount);

            if (from == address(0)) {
                S.protocolFeeLastWithdrawnTime[token] = block.timestamp;
            }
        } else {
            emit WithdrawalFailed(category, from, to, token, amount);
        }
    }
}













library WithdrawTransaction
{

    using BytesUtil            for bytes;
    using FloatUtil            for uint;
    using MathUint             for uint;
    using ExchangeMode         for ExchangeData.State;
    using ExchangeSignatures   for ExchangeData.State;
    using ExchangeWithdrawals  for ExchangeData.State;

    bytes32 constant public WITHDRAWAL_TYPEHASH = keccak256(
        "Withdrawal(address owner,uint32 accountID,uint16 tokenID,uint96 amount,uint16 feeTokenID,uint96 maxFee,address to,bytes extraData,uint256 minGas,uint32 validUntil,uint32 storageID)"
    );

    struct Withdrawal
    {
        uint    withdrawalType;
        address from;
        uint32  fromAccountID;
        uint16  tokenID;
        uint96  amount;
        uint16  feeTokenID;
        uint96  maxFee;
        uint96  fee;
        address to;
        bytes   extraData;
        uint    minGas;
        uint32  validUntil;
        uint32  storageID;
        bytes20 onchainDataHash;
    }

    struct WithdrawalAuxiliaryData
    {
        bool  storeRecipient;
        uint  gasLimit;
        bytes signature;

        uint    minGas;
        address to;
        bytes   extraData;
        uint96  maxFee;
        uint32  validUntil;
    }

    function process(
        ExchangeData.State        storage S,
        ExchangeData.BlockContext memory  ctx,
        bytes                     memory  data,
        uint                              offset,
        bytes                     memory  auxiliaryData
        )
        internal
    {

        Withdrawal memory withdrawal = readTx(data, offset);
        WithdrawalAuxiliaryData memory auxData = abi.decode(auxiliaryData, (WithdrawalAuxiliaryData));

        bytes20 onchainDataHash = hashOnchainData(
            auxData.minGas,
            auxData.to,
            auxData.extraData
        );
        require(withdrawal.onchainDataHash == onchainDataHash, "INVALID_WITHDRAWAL_DATA");

        withdrawal.to = auxData.to;
        withdrawal.minGas = auxData.minGas;
        withdrawal.extraData = auxData.extraData;
        withdrawal.maxFee = auxData.maxFee == 0 ? withdrawal.fee : auxData.maxFee;
        withdrawal.validUntil = auxData.validUntil;

        require(withdrawal.from == address(0) || withdrawal.to != address(0), "INVALID_WITHDRAWAL_RECIPIENT");

        if (withdrawal.withdrawalType == 0) {
        } else if (withdrawal.withdrawalType == 1) {
            require(ctx.timestamp < withdrawal.validUntil, "WITHDRAWAL_EXPIRED");
            require(withdrawal.fee <= withdrawal.maxFee, "WITHDRAWAL_FEE_TOO_HIGH");

            bytes32 txHash = hashTx(ctx.DOMAIN_SEPARATOR, withdrawal);
            S.requireAuthorizedTx(withdrawal.from, auxData.signature, txHash);
        } else if (withdrawal.withdrawalType == 2 || withdrawal.withdrawalType == 3) {
            require(withdrawal.from == withdrawal.to, "INVALID_WITHDRAWAL_ADDRESS");

            require(withdrawal.fee == 0, "FEE_NOT_ZERO");

            require(withdrawal.extraData.length == 0, "AUXILIARY_DATA_NOT_ALLOWED");

            ExchangeData.ForcedWithdrawal memory forcedWithdrawal =
                S.pendingForcedWithdrawals[withdrawal.fromAccountID][withdrawal.tokenID];

            if (forcedWithdrawal.timestamp != 0) {
                if (withdrawal.withdrawalType == 2) {
                    require(withdrawal.from == forcedWithdrawal.owner, "INCONSISENT_OWNER");
                } else { //withdrawal.withdrawalType == 3
                    require(withdrawal.from != forcedWithdrawal.owner, "INCONSISENT_OWNER");
                    require(withdrawal.amount == 0, "UNAUTHORIZED_WITHDRAWAL");
                }

                delete S.pendingForcedWithdrawals[withdrawal.fromAccountID][withdrawal.tokenID];
                S.numPendingForcedTransactions--;
            } else {
                require(
                    withdrawal.fromAccountID == ExchangeData.ACCOUNTID_PROTOCOLFEE() ||
                    S.isShutdown(),
                    "FULL_WITHDRAWAL_UNAUTHORIZED"
                );
            }
        } else {
            revert("INVALID_WITHDRAWAL_TYPE");
        }

        address recipient = S.withdrawalRecipient[withdrawal.from][withdrawal.to][withdrawal.tokenID][withdrawal.amount][withdrawal.storageID];
        if (recipient != address(0)) {
            require (withdrawal.extraData.length == 0, "AUXILIARY_DATA_NOT_ALLOWED");

            withdrawal.to = recipient;
            withdrawal.minGas = 0;

        } else if (auxData.storeRecipient) {
            require(withdrawal.to != address(0), "INVALID_DESTINATION_ADDRESS");
            S.withdrawalRecipient[withdrawal.from][withdrawal.to][withdrawal.tokenID][withdrawal.amount][withdrawal.storageID] = withdrawal.to;
        }

        require(auxData.gasLimit >= withdrawal.minGas, "OUT_OF_GAS_FOR_WITHDRAWAL");

        S.distributeWithdrawal(
            withdrawal.from,
            withdrawal.to,
            withdrawal.tokenID,
            withdrawal.amount,
            withdrawal.extraData,
            auxData.gasLimit
        );
    }

    function readTx(
        bytes memory data,
        uint         offset
        )
        internal
        pure
        returns (Withdrawal memory withdrawal)
    {

        uint _offset = offset;
        withdrawal.withdrawalType = data.toUint8(_offset);
        _offset += 1;
        withdrawal.from = data.toAddress(_offset);
        _offset += 20;
        withdrawal.fromAccountID = data.toUint32(_offset);
        _offset += 4;
        withdrawal.tokenID = data.toUint16(_offset);
        _offset += 2;
        withdrawal.amount = data.toUint96(_offset);
        _offset += 12;
        withdrawal.feeTokenID = data.toUint16(_offset);
        _offset += 2;
        withdrawal.fee = uint(data.toUint16(_offset)).decodeFloat(16);
        _offset += 2;
        withdrawal.storageID = data.toUint32(_offset);
        _offset += 4;
        withdrawal.onchainDataHash = data.toBytes20(_offset);
        _offset += 20;
    }

    function hashTx(
        bytes32 DOMAIN_SEPARATOR,
        Withdrawal memory withdrawal
        )
        internal
        pure
        returns (bytes32)
    {

        return EIP712.hashPacked(
            DOMAIN_SEPARATOR,
            keccak256(
                abi.encode(
                    WITHDRAWAL_TYPEHASH,
                    withdrawal.from,
                    withdrawal.fromAccountID,
                    withdrawal.tokenID,
                    withdrawal.amount,
                    withdrawal.feeTokenID,
                    withdrawal.maxFee,
                    withdrawal.to,
                    keccak256(withdrawal.extraData),
                    withdrawal.minGas,
                    withdrawal.validUntil,
                    withdrawal.storageID
                )
            )
        );
    }

    function hashOnchainData(
        uint    minGas,
        address to,
        bytes   memory extraData
        )
        internal
        pure
        returns (bytes20)
    {

        return bytes20(keccak256(
            abi.encodePacked(
                minGas,
                to,
                extraData
            )
        ));
    }
}









library TransactionReader {

    using BlockReader       for ExchangeData.Block;
    using TransactionReader for ExchangeData.Block;
    using BytesUtil         for bytes;

    function readDeposit(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (DepositTransaction.Deposit memory)
    {

        bytes memory data = _block.readTx(txIdx, ExchangeData.TransactionType.DEPOSIT);
        return DepositTransaction.readTx(data, 1);
    }

    function readWithdrawal(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (WithdrawTransaction.Withdrawal memory)
    {

        bytes memory data = _block.readTx(txIdx, ExchangeData.TransactionType.WITHDRAWAL);
        return WithdrawTransaction.readTx(data, 1);
    }

    function readAmmUpdate(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (AmmUpdateTransaction.AmmUpdate memory)
    {

        bytes memory data = _block.readTx(txIdx, ExchangeData.TransactionType.AMM_UPDATE);
        return AmmUpdateTransaction.readTx(data, 1);
    }

    function readTransfer(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (TransferTransaction.Transfer memory)
    {

        bytes memory data = _block.readTx(txIdx, ExchangeData.TransactionType.TRANSFER);
        return TransferTransaction.readTx(data, 1);
    }

    function readSignatureVerification(
        ExchangeData.Block memory _block,
        uint txIdx
        )
        internal
        pure
        returns (SignatureVerificationTransaction.SignatureVerification memory)
    {

        bytes memory data = _block.readTx(txIdx, ExchangeData.TransactionType.SIGNATURE_VERIFICATION);
        return SignatureVerificationTransaction.readTx(data, 1);
    }

    function readTx(
        ExchangeData.Block memory _block,
        uint txIdx,
        ExchangeData.TransactionType txType
        )
        internal
        pure
        returns (bytes memory data)
    {

        data = _block.readTransactionData(txIdx);
        require(txType == ExchangeData.TransactionType(data.toUint8(0)), "UNEXPTECTED_TX_TYPE");
    }

    function createMinimalBlock(
        ExchangeData.Block memory _block,
        uint txIdx,
        uint16 numTransactions
        )
        internal
        pure
        returns (ExchangeData.Block memory)
    {

        ExchangeData.Block memory minimalBlock = ExchangeData.Block({
            blockType: _block.blockType,
            blockSize: numTransactions,
            blockVersion: _block.blockVersion,
            data: new bytes(0),
            proof: _block.proof,
            storeBlockInfoOnchain: _block.storeBlockInfoOnchain,
            auxiliaryData: new ExchangeData.AuxiliaryData[](0),
            offchainData: new bytes(0)
        });

        bytes memory header = _block.data.slice(0, BlockReader.OFFSET_TO_TRANSACTIONS);

        uint txDataOffset = BlockReader.OFFSET_TO_TRANSACTIONS +
            txIdx * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_1();
        bytes memory dataPart1 = _block.data.slice(txDataOffset, numTransactions * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_1());
        txDataOffset = BlockReader.OFFSET_TO_TRANSACTIONS +
            _block.blockSize * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_1() +
            txIdx * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_2();
        bytes memory dataPart2 = _block.data.slice(txDataOffset, numTransactions * ExchangeData.TX_DATA_AVAILABILITY_SIZE_PART_2());

        minimalBlock.data = header.concat(dataPart1).concat(dataPart2);

        return minimalBlock;
    }
}











library AmmUtil
{

    using AddressUtil       for address;
    using BytesUtil         for bytes;
    using ERC20SafeTransfer for address;
    using MathUint          for uint;
    using TransactionReader for ExchangeData.Block;

    uint8 public constant L2_SIGNATURE_TYPE = 16;

    function verifySignatureL2(
        AmmData.Context     memory  ctx,
        ExchangeData.Block  memory  _block,
        address                     owner,
        bytes32                     txHash,
        bytes               memory  signature
        )
        internal
        pure
    {

        require(signature.toUint8(0) == L2_SIGNATURE_TYPE, "INVALID_SIGNATURE_TYPE");

        SignatureVerificationTransaction.SignatureVerification memory verification = _block.readSignatureVerification(ctx.txIdx++);

        require(
            verification.owner == owner &&
            verification.data == uint(txHash) >> 3,
            "INVALID_OFFCHAIN_L2_APPROVAL"
        );
    }

    function isAlmostEqualAmount(
        uint96 amount,
        uint96 targetAmount
        )
        internal
        pure
        returns (bool)
    {

        if (targetAmount == 0) {
            return amount == 0;
        } else {
            uint ratio = (uint(amount) * 100000) / uint(targetAmount);
            return (100000 - 8) <= ratio && ratio <= (100000 + 8);
        }
    }

    function isAlmostEqualFee(
        uint96 amount,
        uint96 targetAmount
        )
        internal
        pure
        returns (bool)
    {

        if (targetAmount == 0) {
            return amount == 0;
        } else {
            uint ratio = (uint(amount) * 1000) / uint(targetAmount);
            return (1000 - 5) <= ratio && ratio <= (1000 + 5);
        }
    }

    function transferIn(
        address token,
        uint    amount
        )
        internal
    {

        if (token == address(0)) {
            require(msg.value == amount, "INVALID_ETH_VALUE");
        } else if (amount > 0) {
            token.safeTransferFromAndVerify(msg.sender, address(this), amount);
        }
    }

    function transferOut(
        address token,
        uint    amount,
        address to
        )
        internal
    {

        if (token == address(0)) {
            to.sendETHAndVerify(amount, gasleft());
        } else {
            token.safeTransferAndVerify(to, amount);
        }
    }
}







library AmmExitRequest
{

    bytes32 constant public POOLEXIT_TYPEHASH = keccak256(
        "PoolExit(address owner,uint96 burnAmount,uint32 burnStorageID,uint96[] exitMinAmounts,uint96 fee,uint32 validUntil)"
    );

    event PoolExitRequested(AmmData.PoolExit exit, bool force);

    function exitPool(
        AmmData.State storage S,
        uint96                burnAmount,
        uint96[]     calldata exitMinAmounts,
        bool                  force
        )
        public
    {

        require(burnAmount > 0, "INVALID_BURN_AMOUNT");
        require(exitMinAmounts.length == S.tokens.length, "INVALID_EXIT_AMOUNTS");

        AmmData.PoolExit memory exit = AmmData.PoolExit({
            owner: msg.sender,
            burnAmount: burnAmount,
            burnStorageID: 0,
            exitMinAmounts: exitMinAmounts,
            fee: 0,
            validUntil: uint32(block.timestamp + S.sharedConfig.maxForcedExitAge())
        });

        if (force) {
            require(S.forcedExit[msg.sender].validUntil == 0, "DUPLICATE");
            require(S.forcedExitCount < S.sharedConfig.maxForcedExitCount(), "TOO_MANY_FORCED_EXITS");

            AmmUtil.transferIn(address(this), burnAmount);

            uint feeAmount = S.sharedConfig.forcedExitFee();
            AmmUtil.transferIn(address(0), feeAmount);
            AmmUtil.transferOut(address(0), feeAmount, S.exchange.owner());

            S.forcedExit[msg.sender] = exit;
            S.forcedExitCount++;
        } else {
            AmmUtil.transferIn(address(0), 0);

            bytes32 txHash = hash(S.domainSeparator, exit);
            S.approvedTx[txHash] = true;
        }

        emit PoolExitRequested(exit, force);
    }

    function hash(
        bytes32 domainSeparator,
        AmmData.PoolExit memory exit
        )
        internal
        pure
        returns (bytes32)
    {

        return EIP712.hashPacked(
            domainSeparator,
            keccak256(
                abi.encode(
                    POOLEXIT_TYPEHASH,
                    exit.owner,
                    exit.burnAmount,
                    exit.burnStorageID,
                    keccak256(abi.encodePacked(exit.exitMinAmounts)),
                    exit.fee,
                    exit.validUntil
                )
            )
        );
    }
}