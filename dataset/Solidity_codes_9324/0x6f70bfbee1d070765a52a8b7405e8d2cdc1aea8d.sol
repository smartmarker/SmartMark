
pragma solidity ^0.5.0;




contract Context {

    constructor () internal { }
    function _msgSender() internal view returns (address payable) {

        return msg.sender;
    }
    function _msgData() internal view returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}



interface IERC165 {

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

}

contract ERC165 is IERC165 {

    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;
    mapping(bytes4 => bool) private _supportedInterfaces;

    constructor () internal {
        _registerInterface(_INTERFACE_ID_ERC165);
    }
    function supportsInterface(bytes4 interfaceId) external view returns (bool) {

        return _supportedInterfaces[interfaceId];
    }
    function _registerInterface(bytes4 interfaceId) internal {

        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");
        _supportedInterfaces[interfaceId] = true;
    }
}

library SafeMath {

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, "SafeMath: subtraction overflow");
    }
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, "SafeMath: division by zero");
    }
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);
        uint256 c = a / b;

        return c;
    }
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return mod(a, b, "SafeMath: modulo by zero");
    }
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);
        return a % b;
    }
}
library Address {

    function isContract(address account) internal view returns (bool) {

        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        assembly { codehash := extcodehash(account) }
        return (codehash != accountHash && codehash != 0x0);
    }
    function toPayable(address account) internal pure returns (address payable) {

        return address(uint160(account));
    }
    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call.value(amount)("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}


contract IERC721 is IERC165 {

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    function balanceOf(address owner) public view returns (uint256 balance);

    function ownerOf(uint256 tokenId) public view returns (address owner);

    function safeTransferFrom(address from, address to, uint256 tokenId) public;

    function transferFrom(address from, address to, uint256 tokenId) public;

    function approve(address to, uint256 tokenId) public;

    function getApproved(uint256 tokenId) public view returns (address operator);


    function setApprovalForAll(address operator, bool _approved) public;

    function isApprovedForAll(address owner, address operator) public view returns (bool);



    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public;

}

contract IERC721Receiver {

    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory data)
    public returns (bytes4);

}

contract ERC721 is Context, ERC165, IERC721 {

    using SafeMath for uint256;
    using Address for address;

    bytes4 private constant _ERC721_RECEIVED = 0x150b7a02;
    mapping (uint256 => address) private _tokenOwner;
    mapping (uint256 => address) private _tokenApprovals;
    uint256 internal _totalSupply;

    mapping (address => mapping (address => bool)) private _operatorApprovals;
    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;

    constructor () public {
        _registerInterface(_INTERFACE_ID_ERC721);
    }

    function totalSupply() public view returns (uint256) {

      return _totalSupply;
    }
    
    function ownerOf(uint256 tokenId) public view returns (address) {

        address owner = _tokenOwner[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");

        return owner;
    }
    function approve(address to, uint256 tokenId) public {

        address owner = ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }
    function getApproved(uint256 tokenId) public view returns (address) {

        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }
    function setApprovalForAll(address to, bool approved) public {

        require(to != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][to] = approved;
        emit ApprovalForAll(_msgSender(), to, approved);
    }
    function isApprovedForAll(address owner, address operator) public view returns (bool) {

        return _operatorApprovals[owner][operator];
    }
    function transferFrom(address from, address to, uint256 tokenId) public {

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transferFrom(from, to, tokenId);
    }
    function safeTransferFrom(address from, address to, uint256 tokenId) public {

        safeTransferFrom(from, to, tokenId, "");
    }
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransferFrom(from, to, tokenId, _data);
    }
    function _safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) internal {

        _transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
    function _exists(uint256 tokenId) internal view returns (bool) {

        address owner = _tokenOwner[tokenId];
        return owner != address(0);
    }
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {

        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }
    function _safeMint(address to, uint256 tokenId) internal {

        _safeMint(to, tokenId, "");
    }
    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal {

        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
    function _mint(address to, uint256 tokenId) internal {

        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _tokenOwner[tokenId] = to;
        _totalSupply = _totalSupply.add(1);

        emit Transfer(address(0), to, tokenId);
    }
    function _burn(address owner, uint256 tokenId) internal {

        require(ownerOf(tokenId) == owner, "ERC721: burn of token that is not own");

        _clearApproval(tokenId);

        _tokenOwner[tokenId] = address(0);
        _totalSupply = _totalSupply.sub(1);

        emit Transfer(owner, address(0), tokenId);
    }
    function _burn(uint256 tokenId) internal {

        _burn(ownerOf(tokenId), tokenId);
    }
    function _transferFrom(address from, address to, uint256 tokenId) internal {

        require(ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _clearApproval(tokenId);

        _tokenOwner[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
        internal returns (bool)
    {

        if (!to.isContract()) {
            return true;
        }
        (bool success, bytes memory returndata) = to.call(abi.encodeWithSelector(
            IERC721Receiver(to).onERC721Received.selector,
            _msgSender(),
            from,
            tokenId,
            _data
        ));
        if (!success) {
            if (returndata.length > 0) {
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert("ERC721: transfer to non ERC721Receiver implementer");
            }
        } else {
            bytes4 retval = abi.decode(returndata, (bytes4));
            return (retval == _ERC721_RECEIVED);
        }
    }
    function _clearApproval(uint256 tokenId) private {

        if (_tokenApprovals[tokenId] != address(0)) {
            _tokenApprovals[tokenId] = address(0);
        }
    }
}



contract IERC721Enumerable is IERC721 {

    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256 tokenId);

}

contract ERC721Enumerable is Context, ERC165, ERC721, IERC721Enumerable {

    mapping(address => uint256[]) private _ownedTokens;
    mapping(uint256 => uint256) private _ownedTokensIndex;
    bytes4 private constant _INTERFACE_ID_ERC721_ENUMERABLE = 0x780e9d63;

    constructor () public {
        _registerInterface(_INTERFACE_ID_ERC721_ENUMERABLE);
    }
    
    function balanceOf(address owner) public view returns (uint256) {

        require(owner != address(0), "ERC721: balance query for the zero address");

        return _ownedTokens[owner].length;
    }
    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256) {

        require(index < balanceOf(owner), "ERC721Enumerable: owner index out of bounds");
        return _ownedTokens[owner][index];
    }
    function _transferFrom(address from, address to, uint256 tokenId) internal {

        super._transferFrom(from, to, tokenId);

        _removeTokenFromOwnerEnumeration(from, tokenId);

        _addTokenToOwnerEnumeration(to, tokenId);
    }
    function _mint(address to, uint256 tokenId) internal {

        super._mint(to, tokenId);

        _addTokenToOwnerEnumeration(to, tokenId);
    }
    function _burn(address owner, uint256 tokenId) internal {

        super._burn(owner, tokenId);

        _removeTokenFromOwnerEnumeration(owner, tokenId);
        _ownedTokensIndex[tokenId] = 0;
    }
    function _tokensOfOwner(address owner) internal view returns (uint256[] storage) {

        return _ownedTokens[owner];
    }
    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) private {

        _ownedTokensIndex[tokenId] = _ownedTokens[to].length;
        _ownedTokens[to].push(tokenId);
    }
    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) private {

        uint256 lastTokenIndex = _ownedTokens[from].length.sub(1);
        uint256 tokenIndex = _ownedTokensIndex[tokenId];
        if (tokenIndex != lastTokenIndex) {
            uint256 lastTokenId = _ownedTokens[from][lastTokenIndex];

            _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
            _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index
        }
        _ownedTokens[from].length--;
    }
}



contract IERC721Metadata is IERC721 {

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function tokenURI(uint256 tokenId) external view returns (string memory);

}

contract ERC721Metadata is Context, ERC165, ERC721, IERC721Metadata {

    string private _name;
    string private _symbol;
    string private _baseURI;
    mapping(uint256 => string) private _tokenURIs;
    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;

    constructor (string memory name, string memory symbol) public {
        _name = name;
        _symbol = symbol;

        _registerInterface(_INTERFACE_ID_ERC721_METADATA);
    }
    function name() external view returns (string memory) {

        return _name;
    }
    function symbol() external view returns (string memory) {

        return _symbol;
    }
    function tokenURI(uint256 tokenId) external view returns (string memory) {

        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory _tokenURI = _tokenURIs[tokenId];

        if (bytes(_tokenURI).length == 0) {
            return "";
        } else {
            return string(abi.encodePacked(_baseURI, _tokenURI));
        }
    }
    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {

        require(_exists(tokenId), "ERC721Metadata: URI set of nonexistent token");
        _tokenURIs[tokenId] = _tokenURI;
    }
    function _setBaseURI(string memory baseURI) internal {

        _baseURI = baseURI;
    }
    function baseURI() external view returns (string memory) {

        return _baseURI;
    }
    function _burn(address owner, uint256 tokenId) internal {

        super._burn(owner, tokenId);

        if (bytes(_tokenURIs[tokenId]).length != 0) {
            delete _tokenURIs[tokenId];
        }
    }
}

contract ERC721Full is ERC721, ERC721Enumerable, ERC721Metadata {

    constructor (string memory name, string memory symbol) public ERC721Metadata(name, symbol) {
    }
}


contract Ownable is Context {

    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }
    function owner() public view returns (address) {

        return _owner;
    }
    modifier onlyOwner() {

        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }
    function isOwner() public view returns (bool) {

        return _msgSender() == _owner;
    }
    function renounceOwnership() public onlyOwner {

        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }
    function transferOwnership(address newOwner) public onlyOwner {

        _transferOwnership(newOwner);
    }
    function _transferOwnership(address newOwner) internal {

        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract ReentrancyGuard {

    bool private _notEntered;

    constructor () internal {
        _notEntered = true;
    }
    modifier nonReentrant() {

        require(_notEntered, "ReentrancyGuard: reentrant call");
        _notEntered = false;

        _;

        _notEntered = true;
    }
}



interface IERC20 {

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    function decimals() external returns (uint8);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

library SafeERC20 {

    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {

        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function callOptionalReturn(IERC20 token, bytes memory data) private {


        require(address(token).isContract(), "SafeERC20: call to non-contract");

        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}


interface IClaims {

    function getClaimbyIndex(uint _claimId) external view returns (
        uint claimId,
        uint status,
        int8 finalVerdict,
        address claimOwner,
        uint coverId
    );

    function submitClaim(uint coverId) external;

}

interface IClaimsData {

    function actualClaimLength() external view returns(uint);

}

interface IDSValue {

    function peek() external view returns (bytes32, bool);

    function read() external view returns (bytes32);

}


interface INXMMaster {

    function tokenAddress() external view returns(address);

    function owner() external view returns(address);

    function pauseTime() external view returns(uint);

    function masterInitialized() external view returns(bool);

    function isPause() external view returns(bool check);

    function isMember(address _add) external view returns(bool);

    function getLatestAddress(bytes2 _contractName) external view returns(address payable contractAddress);

}

interface IMemberRoles {

    function switchMembership(address) external;

}

interface INXMToken {

    function balanceOf(address owner) external view returns (uint256);

    function approve(address spender, uint256 value) external returns (bool);

}

interface IPool1  {

    function changeDependentContractAddress() external;

    function makeCoverBegin(
        address smartCAdd,
        bytes4 coverCurr,
        uint[] calldata coverDetails,
        uint16 coverPeriod,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    )
        external
        payable;

    function makeCoverUsingCA(
        address smartCAdd,
        bytes4 coverCurr,
        uint[] calldata coverDetails,
        uint16 coverPeriod,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    )
        external;

    function getWei(uint amount) external view returns(uint);

    function sellNXMTokens(uint _amount) external  returns (bool);

}


interface IPoolData {


    struct ApiId {
        bytes4 typeOf;
        bytes4 currency;
        uint id;
        uint64 dateAdd;
        uint64 dateUpd;
    }

    struct CurrencyAssets {
        address currAddress;
        uint baseMin;
        uint varMin;
    }

    struct InvestmentAssets {
        address currAddress;
        bool status;
        uint64 minHoldingPercX100;
        uint64 maxHoldingPercX100;
        uint8 decimals;
    }

    struct IARankDetails {
        bytes4 maxIACurr;
        uint64 maxRate;
        bytes4 minIACurr;
        uint64 minRate;
    }

    struct McrData {
        uint mcrPercx100;
        uint mcrEther;
        uint vFull; //Pool funds
        uint64 date;
    }

    function setCapReached(uint val) external;

    function getInvestmentAssetDecimals(bytes4 curr) external returns(uint8 decimal);

    function getCurrencyAssetAddress(bytes4 curr) external view returns(address);

    function getInvestmentAssetAddress(bytes4 curr) external view returns(address);

    function getInvestmentAssetStatus(bytes4 curr) external view returns(bool status);

}

interface IQuotationData {


    enum HCIDStatus { NA, kycPending, kycPass, kycFailedOrRefunded, kycPassNoCover }
    enum CoverStatus { Active, ClaimAccepted, ClaimDenied, CoverExpired, ClaimSubmitted, Requested }

    struct Cover {
        address payable memberAddress;
        bytes4 currencyCode;
        uint sumAssured;
        uint16 coverPeriod;
        uint validUntil;
        address scAddress;
        uint premiumNXM;
    }

    struct HoldCover {
        uint holdCoverId;
        address payable userAddress;
        address scAddress;
        bytes4 coverCurr;
        uint[] coverDetails;
        uint16 coverPeriod;
    }

    function getCoverLength() external returns(uint len);

    function getAuthQuoteEngine() external returns(address _add);

    function getAllCoversOfUser(address _add) external returns(uint[] memory allCover);

    function getUserCoverLength(address _add) external returns(uint len);

    function getCoverStatusNo(uint _cid) external returns(uint8);

    function getCoverPeriod(uint _cid) external returns(uint32 cp);

    function getCoverSumAssured(uint _cid) external returns(uint sa);

    function getCurrencyOfCover(uint _cid) external returns(bytes4 curr);

    function getValidityOfCover(uint _cid) external returns(uint date);

    function getscAddressOfCover(uint _cid) external returns(uint, address);

    function getCoverMemberAddress(uint _cid) external returns(address payable _add);

    function getCoverPremiumNXM(uint _cid) external returns(uint _premiumNXM);

    function getCoverDetailsByCoverID1(
        uint _cid
    )
        external
        view
        returns (
            uint cid,
            address _memberAddress,
            address _scAddress,
            bytes4 _currencyCode,
            uint _sumAssured,
            uint premiumNXM
        );

    function getCoverDetailsByCoverID2(
        uint _cid
    )
        external
        view
        returns (
            uint cid,
            uint8 status,
            uint sumAssured,
            uint16 coverPeriod,
            uint validUntil
        );

    function getHoldedCoverDetailsByID1(
        uint _hcid
    )
        external
        view
        returns (
            uint hcid,
            address scAddress,
            bytes4 coverCurr,
            uint16 coverPeriod
        );

    function getUserHoldedCoverLength(address _add) external returns (uint);

    function getUserHoldedCoverByIndex(address _add, uint index) external returns (uint);

    function getHoldedCoverDetailsByID2(
        uint _hcid
    )
        external
        returns (
            uint hcid,
            address payable memberAddress,
            uint[] memory coverDetails
        );

    function getTotalSumAssuredSC(address _add, bytes4 _curr) external returns(uint amount);


}

interface ITokenData {

    function lockTokenTimeAfterCoverExp() external returns (uint);

}


interface IyInsure {

    struct Token {
        uint expirationTimestamp;
        bytes4 coverCurrency;
        uint coverAmount;
        uint coverPrice;
        uint coverPriceNXM;
        uint expireTime;
        uint generationTime;
        uint coverId;
        bool claimInProgress;
        uint claimId;
    }
    
    function transferFrom(address sender, address recipient, uint256 amount) external;

    function submitClaim(uint256 tokenId) external;

    function tokens(uint256 tokenId) external returns (uint, bytes4, uint, uint, uint, uint, uint, uint, bool, uint);

}

contract arNFT is
    ERC721Full("ArmorNFT", "arNFT"),
    Ownable,
    ReentrancyGuard {

    
    using SafeMath for uint;
    using SafeERC20 for IERC20;
    
    bytes4 internal constant ethCurrency = "ETH";
    
    mapping (uint256 => uint256) private claimIds;
    
    mapping (uint256 => uint256) private coverPrices;
    
    mapping(uint256 => uint256) private swapIds;

    bool public swapActivated;

    INXMMaster public nxMaster;

    IyInsure public ynft;
    
    enum CoverStatus {
        Active,
        ClaimAccepted,
        ClaimDenied,
        CoverExpired,
        ClaimSubmitted,
        Requested
    }
    
    enum ClaimStatus {
        PendingClaimAssessorVote, // 0
        PendingClaimAssessorVoteDenied, // 1
        PendingClaimAssessorVoteThresholdNotReachedAccept, // 2
        PendingClaimAssessorVoteThresholdNotReachedDeny, // 3
        PendingClaimAssessorConsensusNotReachedAccept, // 4
        PendingClaimAssessorConsensusNotReachedDeny, // 5
        FinalClaimAssessorVoteDenied, // 6
        FinalClaimAssessorVoteAccepted, // 7
        FinalClaimAssessorVoteDeniedMVAccepted, // 8
        FinalClaimAssessorVoteDeniedMVDenied, // 9
        FinalClaimAssessorVotAcceptedMVNoDecision, // 10
        FinalClaimAssessorVoteDeniedMVNoDecision, // 11
        ClaimAcceptedPayoutPending, // 12
        ClaimAcceptedNoPayout, // 13
        ClaimAcceptedPayoutDone // 14
    }

    event SwappedYInsure (
        uint256 indexed yInsureTokenId,
        uint256 indexed coverId
    );

    event ClaimSubmitted (
        uint256 indexed coverId,
        uint256 indexed claimId
    );
    
    event ClaimRedeemed (
        address indexed receiver,
        bytes4 indexed currency,
        uint256 value
    );

    event BuyCover (
        uint indexed coverId,
        address indexed buyer,
        address indexed coveredContract,
        bytes4 currency,
        uint256 coverAmount,
        uint256 coverPrice,
        uint256 startTime,
        uint16 coverPeriod
    );

    
    modifier onlyTokenApprovedOrOwner(uint256 _tokenId) {

        require(_isApprovedOrOwner(msg.sender, _tokenId), "Not approved or owner");
        _;
    }

    constructor(address _nxMaster, address _ynft) public {
        nxMaster = INXMMaster(_nxMaster);
        ynft = IyInsure(_ynft);
    }
    
    function () payable external {}
    
    function buyCover(
        address _coveredContractAddress,
        bytes4 _coverCurrency,
        uint[] calldata _coverDetails,
        uint16 _coverPeriod,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external payable {

        uint256 coverPrice = _coverDetails[1];

        if (_coverCurrency == "ETH") {
            require(msg.value == coverPrice, "Incorrect value sent");
        } else {
            IERC20 erc20 = IERC20(_getCurrencyAssetAddress(_coverCurrency));

            require(msg.value == 0, "Eth not required when buying with erc20");
            erc20.safeTransferFrom(msg.sender, address(this), coverPrice);
        }
        
        uint256 coverId = _buyCover(_coveredContractAddress, _coverCurrency, _coverDetails, _coverPeriod, _v, _r, _s);
        _mint(msg.sender, coverId);
        
        emit BuyCover(coverId, msg.sender, _coveredContractAddress, _coverCurrency, _coverDetails[0], _coverDetails[1], 
                      block.timestamp, _coverPeriod);
    }
    
    function submitClaim(uint256 _tokenId) external onlyTokenApprovedOrOwner(_tokenId) {

        if (swapIds[_tokenId] != 0) {
            _submitYnftClaim(_tokenId);
            return;
        }
        
        (uint256 coverId, uint8 coverStatus, /*sumAssured*/, /*coverPeriod*/, uint256 validUntil) = _getCover2(_tokenId);
        if (claimIds[_tokenId] > 0) {
            require(coverStatus == uint8(CoverStatus.ClaimDenied),
            "Can submit another claim only if the previous one was denied.");
        }
        
        require(validUntil + _getLockTokenTimeAfterCoverExpiry() >= block.timestamp, "Token is expired");
        uint256 claimId = _submitClaim(coverId);
        claimIds[_tokenId] = claimId;
        
        emit ClaimSubmitted(coverId, claimId);
    }
    
    function redeemClaim(uint256 _tokenId) public onlyTokenApprovedOrOwner(_tokenId)  nonReentrant {

        require(claimIds[_tokenId] != 0, "No claim is in progress.");
        
        (/*cid*/, /*memberAddress*/, /*scAddress*/, bytes4 currencyCode, /*sumAssured*/, /*premiumNXM*/) = _getCover1(_tokenId);
        ( , uint8 coverStatus, uint256 sumAssured, , ) = _getCover2(_tokenId);
        
        require(coverStatus == uint8(CoverStatus.ClaimAccepted), "Claim is not accepted");
        require(_payoutIsCompleted(claimIds[_tokenId]), "Claim accepted but payout not completed");
       
        _burn(_tokenId);
        _sendAssuredSum(currencyCode, sumAssured);
        
        emit ClaimRedeemed(msg.sender, currencyCode, sumAssured);
    }
    
    function activateSwap()
      public
      onlyOwner
    {

        require(!swapActivated, "Already Activated");
        swapActivated = true;
    }

    function swapYnft(uint256 _ynftTokenId)
      public
    {

        require(swapActivated, "Swap is not activated yet");
        ynft.transferFrom(msg.sender, address(this), _ynftTokenId);
        
        (uint256 coverId, uint256 claimId) = _getCoverAndClaim(_ynftTokenId);

        _mint(msg.sender, coverId);

        swapIds[coverId] = _ynftTokenId;
        claimIds[coverId] = claimId;
        
        emit SwappedYInsure(_ynftTokenId, coverId);
    }
    
    function batchSwapYnft(uint256[] calldata _tokenIds)
      external
    {

        for (uint256 i = 0; i < _tokenIds.length; i++) {
            swapYnft(_tokenIds[i]);
        }
    }
    
    function approveToken(address _tokenAddress)
      external
    {

        IPool1 pool1 = IPool1(nxMaster.getLatestAddress("P1"));
        address payable pool1Address = address(uint160(address(pool1)));
        IERC20 erc20 = IERC20(_tokenAddress);
        erc20.safeApprove( pool1Address, uint256(-1) );
    }
    
    function getToken(uint256 _tokenId)
      external
      view
    returns (uint256 cid, 
             uint8 status, 
             uint256 sumAssured,
             uint16 coverPeriod, 
             uint256 validUntil, 
             address scAddress, 
             bytes4 currencyCode, 
             uint256 premiumNXM,
             uint256 coverPrice,
             uint256 claimId)
    {

        (/*cid*/, /*memberAddress*/, scAddress, currencyCode, /*sumAssured*/, premiumNXM) = _getCover1(_tokenId);
        (cid, status, sumAssured, coverPeriod, validUntil) = _getCover2(_tokenId);
        coverPrice = coverPrices[_tokenId];
        claimId = claimIds[_tokenId];
    }
    
    function getCoverStatus(uint256 _tokenId) external view returns (uint8 coverStatus, bool payoutCompleted) {

        (, coverStatus, , , ) = _getCover2(_tokenId);
        payoutCompleted = _payoutIsCompleted(claimIds[_tokenId]);
    }
    
    function getMemberRoles() public view returns (address) {

        return nxMaster.getLatestAddress("MR");
    }
    
    function switchMembership(address _newMembership) external onlyOwner {

        IERC20 nxmToken = IERC20(nxMaster.tokenAddress());
        nxmToken.safeApprove(getMemberRoles(),uint(-1));
        IMemberRoles(getMemberRoles()).switchMembership(_newMembership);
    }
    
    function _buyCover(
        address _coveredContractAddress,
        bytes4 _coverCurrency,
        uint[] memory _coverDetails,
        uint16 _coverPeriod,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal returns (uint256 coverId) {

    
        uint256 coverPrice = _coverDetails[1];
        IPool1 pool1 = IPool1(nxMaster.getLatestAddress("P1"));

        if (_coverCurrency == "ETH") {
            pool1.makeCoverBegin.value(coverPrice)(_coveredContractAddress, _coverCurrency, _coverDetails, _coverPeriod, _v, _r, _s);
        } else {
            pool1.makeCoverUsingCA(_coveredContractAddress, _coverCurrency, _coverDetails, _coverPeriod, _v, _r, _s);
        }
    
        IQuotationData quotationData = IQuotationData(nxMaster.getLatestAddress("QD"));
        coverId = quotationData.getCoverLength().sub(1);
        
        coverPrices[coverId] = coverPrice;
    }
    
    function _submitClaim(uint256 _coverId) internal returns (uint256) {

        IClaims claims = IClaims(nxMaster.getLatestAddress("CL"));
        claims.submitClaim(_coverId);
    
        IClaimsData claimsData = IClaimsData(nxMaster.getLatestAddress("CD"));
        uint256 claimId = claimsData.actualClaimLength() - 1;
        return claimId;
    }
    
    function _submitYnftClaim(uint256 _tokenId)
      internal
    {

        uint256 ynftTokenId = swapIds[_tokenId];
        ynft.submitClaim(ynftTokenId);
        
        (/*coverId*/, uint256 claimId) = _getCoverAndClaim(ynftTokenId);
        claimIds[_tokenId] = claimId;
    }

    function _payoutIsCompleted(uint256 _claimId) internal view returns (bool) {

        uint256 status;
        IClaims claims = IClaims(nxMaster.getLatestAddress("CL"));
        (, status, , , ) = claims.getClaimbyIndex(_claimId);
        return status == uint256(ClaimStatus.FinalClaimAssessorVoteAccepted)
            || status == uint256(ClaimStatus.ClaimAcceptedPayoutDone);
    }

    function _sendAssuredSum(bytes4 _coverCurrency, uint256 _sumAssured) internal {

        uint256 claimReward;

        if (_coverCurrency == ethCurrency) {
            claimReward = _sumAssured * (10 ** 18);
            msg.sender.transfer(claimReward);
        } else {
            IERC20 erc20 = IERC20(_getCurrencyAssetAddress(_coverCurrency));
            uint256 decimals = uint256(erc20.decimals());
        
            claimReward = _sumAssured * (10 ** decimals);
            erc20.safeTransfer(msg.sender, claimReward);
        }
    }
    
    function _getCoverAndClaim(uint256 _ynftTokenId)
      internal
    returns (uint256 coverId, uint256 claimId)
    {

       ( , , , , , , , coverId, , claimId) = ynft.tokens(_ynftTokenId);
    }
    
    function _getCover1 (
        uint256 _coverId
    ) internal view returns (
        uint256 cid,
        address memberAddress,
        address scAddress,
        bytes4 currencyCode,
        uint256 sumAssured,
        uint256 premiumNXM
    ) {
        IQuotationData quotationData = IQuotationData(nxMaster.getLatestAddress("QD"));
        return quotationData.getCoverDetailsByCoverID1(_coverId);
    }
    
    function _getCover2 (
        uint256 _coverId
    ) internal view returns (
        uint256 cid,
        uint8 status,
        uint256 sumAssured,
        uint16 coverPeriod,
        uint256 validUntil
    ) {
        IQuotationData quotationData = IQuotationData(nxMaster.getLatestAddress("QD"));
        return quotationData.getCoverDetailsByCoverID2(_coverId);
    }
    
    function _getCurrencyAssetAddress(bytes4 _currency) internal view returns (address) {

        IPoolData pd = IPoolData(nxMaster.getLatestAddress("PD"));
        return pd.getCurrencyAssetAddress(_currency);
    }
    
    function _getTokenAddress() internal view returns (address) {

        return nxMaster.tokenAddress();
    }
    
    function _getLockTokenTimeAfterCoverExpiry() internal returns (uint256) {

        ITokenData tokenData = ITokenData(nxMaster.getLatestAddress("TD"));
        return tokenData.lockTokenTimeAfterCoverExp();
    }
    
    function nxmTokenApprove(address _spender, uint256 _value) public onlyOwner {

        IERC20 nxmToken = IERC20(_getTokenAddress());
        nxmToken.safeApprove(_spender, _value);
    }
}