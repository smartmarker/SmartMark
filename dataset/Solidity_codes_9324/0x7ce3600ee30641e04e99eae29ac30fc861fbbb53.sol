
pragma solidity 0.6.12;

interface IERC1155TokenCreator {

    function tokenCreator(uint256 _tokenId)
    external
    view
    returns (address payable);

}// MIT

pragma solidity 0.6.12;


interface INafter {


    function creatorOfToken(uint256 _tokenId)
    external
    view
    returns (address payable);


    function getServiceFee(uint256 _tokenId)
    external
    view
    returns (uint8);


    function getPriceType(uint256 _tokenId, address _owner)
    external
    view
    returns (uint8);


    function setPrice(uint256 _price, uint256 _tokenId, address _owner) external;


    function setBid(uint256 _bid, address _bidder, uint256 _tokenId, address _owner) external;


    function removeFromSale(uint256 _tokenId, address _owner) external;


    function getTokenIdsLength() external view returns (uint256);


    function getTokenId(uint256 _index) external view returns (uint256);


    function getOwners(uint256 _tokenId)
    external
    view
    returns (address[] memory owners);


    function getIsForSale(uint256 _tokenId, address _owner) external view returns (bool);

}// MIT

pragma solidity 0.6.12;


interface INafterRoyaltyRegistry is IERC1155TokenCreator {

    function getTokenRoyaltyPercentage(
        uint256 _tokenId
    ) external view returns (uint8);


    function calculateRoyaltyFee(
        uint256 _tokenId,
        uint256 _amount
    ) external view returns (uint256);


    function setPercentageForTokenRoyalty(
        uint256 _tokenId,
        uint8 _percentage
    ) external returns (uint8);

}// MIT

pragma solidity >=0.6.0 <0.8.0;

library SafeMath {

    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }

    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        if (b > a) return (false, 0);
        return (true, a - b);
    }

    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        if (b == 0) return (false, 0);
        return (true, a / b);
    }

    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        if (b == 0) return (false, 0);
        return (true, a % b);
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);
        return a - b;
    }

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);
        return a / b;
    }

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);
        return a % b;
    }
}// MIT

pragma solidity >=0.6.0 <0.8.0;

abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}// MIT

pragma solidity >=0.6.0 <0.8.0;

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () internal {
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

pragma solidity >=0.6.0 <0.8.0;

library EnumerableSet {


    struct Set {
        bytes32[] _values;

        mapping (bytes32 => uint256) _indexes;
    }

    function _add(Set storage set, bytes32 value) private returns (bool) {

        if (!_contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function _remove(Set storage set, bytes32 value) private returns (bool) {

        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) { // Equivalent to contains(set, value)

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;


            bytes32 lastvalue = set._values[lastIndex];

            set._values[toDeleteIndex] = lastvalue;
            set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

            set._values.pop();

            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    function _contains(Set storage set, bytes32 value) private view returns (bool) {

        return set._indexes[value] != 0;
    }

    function _length(Set storage set) private view returns (uint256) {

        return set._values.length;
    }

    function _at(Set storage set, uint256 index) private view returns (bytes32) {

        require(set._values.length > index, "EnumerableSet: index out of bounds");
        return set._values[index];
    }


    struct Bytes32Set {
        Set _inner;
    }

    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {

        return _add(set._inner, value);
    }

    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {

        return _remove(set._inner, value);
    }

    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {

        return _contains(set._inner, value);
    }

    function length(Bytes32Set storage set) internal view returns (uint256) {

        return _length(set._inner);
    }

    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {

        return _at(set._inner, index);
    }


    struct AddressSet {
        Set _inner;
    }

    function add(AddressSet storage set, address value) internal returns (bool) {

        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {

        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    function contains(AddressSet storage set, address value) internal view returns (bool) {

        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    function length(AddressSet storage set) internal view returns (uint256) {

        return _length(set._inner);
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {

        return address(uint160(uint256(_at(set._inner, index))));
    }



    struct UintSet {
        Set _inner;
    }

    function add(UintSet storage set, uint256 value) internal returns (bool) {

        return _add(set._inner, bytes32(value));
    }

    function remove(UintSet storage set, uint256 value) internal returns (bool) {

        return _remove(set._inner, bytes32(value));
    }

    function contains(UintSet storage set, uint256 value) internal view returns (bool) {

        return _contains(set._inner, bytes32(value));
    }

    function length(UintSet storage set) internal view returns (uint256) {

        return _length(set._inner);
    }

    function at(UintSet storage set, uint256 index) internal view returns (uint256) {

        return uint256(_at(set._inner, index));
    }
}// MIT

pragma solidity >=0.6.2 <0.8.0;

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

pragma solidity >=0.6.0 <0.8.0;


abstract contract AccessControl is Context {
    using EnumerableSet for EnumerableSet.AddressSet;
    using Address for address;

    struct RoleData {
        EnumerableSet.AddressSet members;
        bytes32 adminRole;
    }

    mapping (bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members.contains(account);
    }

    function getRoleMemberCount(bytes32 role) public view returns (uint256) {
        return _roles[role].members.length();
    }

    function getRoleMember(bytes32 role, uint256 index) public view returns (address) {
        return _roles[role].members.at(index);
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function grantRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to grant");

        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to revoke");

        _revokeRole(role, account);
    }

    function renounceRole(bytes32 role, address account) public virtual {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        emit RoleAdminChanged(role, _roles[role].adminRole, adminRole);
        _roles[role].adminRole = adminRole;
    }

    function _grantRole(bytes32 role, address account) private {
        if (_roles[role].members.add(account)) {
            emit RoleGranted(role, account, _msgSender());
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (_roles[role].members.remove(account)) {
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}// MIT

pragma solidity 0.6.12;


contract NafterRoyaltyRegistry is Ownable, INafterRoyaltyRegistry {

    using SafeMath for uint256;


    uint8 private contractRoyaltyPercentage;

    mapping(address => uint8) public creatorRoyaltyPercentage;
    mapping(address => bool) private creatorRigistered;
    address[] public creators;

    address public nafter;

    mapping(uint256 => uint8)
    private tokenRoyaltyPercentage;

    IERC1155TokenCreator public iERC1155TokenCreator;

    constructor(address _iERC1155TokenCreator) public {
        require(
            _iERC1155TokenCreator != address(0),
            "constructor::Cannot set the null address as an _iERC1155TokenCreator"
        );
        iERC1155TokenCreator = IERC1155TokenCreator(_iERC1155TokenCreator);
    }

    function setIERC1155TokenCreator(address _contractAddress)
    external
    onlyOwner
    {

        require(
            _contractAddress != address(0),
            "setIERC1155TokenCreator::_contractAddress cannot be null"
        );

        iERC1155TokenCreator = IERC1155TokenCreator(_contractAddress);
    }

    function getTokenRoyaltyPercentage(
        uint256 _tokenId
    ) public view override returns (uint8) {

        if (tokenRoyaltyPercentage[_tokenId] > 0) {
            return tokenRoyaltyPercentage[_tokenId];
        }
        address creator =
        iERC1155TokenCreator.tokenCreator(_tokenId);
        if (creatorRoyaltyPercentage[creator] > 0) {
            return creatorRoyaltyPercentage[creator];
        }
        return contractRoyaltyPercentage;
    }

    function getPercentageForTokenRoyalty(
        uint256 _tokenId
    ) external view returns (uint8) {

        return tokenRoyaltyPercentage[_tokenId];
    }

    function setNafter(address _nafter) external onlyOwner {

        nafter = _nafter;
    }

    function setPercentageForTokenRoyalty(
        uint256 _tokenId,
        uint8 _percentage
    ) external override returns (uint8) {

        require(
            msg.sender == iERC1155TokenCreator.tokenCreator(_tokenId) ||
            msg.sender == owner() ||
            msg.sender == nafter,
            "setPercentageForTokenRoyalty::Must be contract owner or creator or nafter"
        );
        require(
            _percentage <= 100,
            "setPercentageForTokenRoyalty::_percentage must be <= 100"
        );
        tokenRoyaltyPercentage[_tokenId] = _percentage;
    }

    function creatorsLength() external view returns (uint256){

        return creators.length;
    }
    function getPercentageForSetERC1155CreatorRoyalty(
        uint256 _tokenId
    ) external view returns (uint8) {

        address creator =
        iERC1155TokenCreator.tokenCreator(_tokenId);
        return creatorRoyaltyPercentage[creator];
    }

    function setPercentageForSetERC1155CreatorRoyalty(
        address _creatorAddress,
        uint8 _percentage
    ) external returns (uint8) {

        require(
            msg.sender == _creatorAddress || msg.sender == owner(),
            "setPercentageForSetERC1155CreatorRoyalty::Must be owner or creator"
        );
        require(
            _percentage <= 100,
            "setPercentageForSetERC1155CreatorRoyalty::_percentage must be <= 100"
        );

        if (creatorRigistered[_creatorAddress] == false) {
            creators.push(_creatorAddress);
        }
        creatorRigistered[_creatorAddress] = true;
        creatorRoyaltyPercentage[_creatorAddress] = _percentage;

    }

    function getPercentageForSetERC1155ContractRoyalty()
    external
    view
    returns (uint8)
    {

        return contractRoyaltyPercentage;
    }

    function restore(address _oldAddress, address _oldNafterAddress, uint256 _startIndex, uint256 _endIndex) external onlyOwner {

        NafterRoyaltyRegistry oldContract = NafterRoyaltyRegistry(_oldAddress);
        INafter oldNafterContract = INafter(_oldNafterAddress);

        uint256 length = oldNafterContract.getTokenIdsLength();
        require(_startIndex < length, "wrong start index");
        require(_endIndex <= length, "wrong end index");

        for (uint i = _startIndex; i < _endIndex; i++) {
            uint256 tokenId = oldNafterContract.getTokenId(i);
            uint8 percentage = oldContract.getPercentageForTokenRoyalty(tokenId);
            if (percentage != 0) {
                tokenRoyaltyPercentage[tokenId] = percentage;
            }
        }

        for (uint i; i < oldContract.creatorsLength(); i++) {
            address creator = oldContract.creators(i);
            creators.push(creator);
            creatorRigistered[creator] = true;
            creatorRoyaltyPercentage[creator] = oldContract.creatorRoyaltyPercentage(creator);
        }
    }

    function setPercentageForSetERC1155ContractRoyalty(
        uint8 _percentage
    ) external onlyOwner returns (uint8) {

        require(
            _percentage <= 100,
            "setPercentageForSetERC1155ContractRoyalty::_percentage must be <= 100"
        );
        contractRoyaltyPercentage = _percentage;
    }

    function calculateRoyaltyFee(
        uint256 _tokenId,
        uint256 _amount
    ) external view override returns (uint256) {

        return
        _amount
        .mul(
            getTokenRoyaltyPercentage(_tokenId)
        )
        .div(100);
    }

    function tokenCreator(uint256 _tokenId)
    external
    view
    override
    returns (address payable)
    {

        return iERC1155TokenCreator.tokenCreator(_tokenId);
    }
}