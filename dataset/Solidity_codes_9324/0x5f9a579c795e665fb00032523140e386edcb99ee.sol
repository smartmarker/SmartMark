
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
}// GPL-3.0-or-later



pragma solidity ^0.7.0;


function _require(bool condition, uint256 errorCode) pure {
    if (!condition) _revert(errorCode);
}

function _revert(uint256 errorCode) pure {
    assembly {

        let units := add(mod(errorCode, 10), 0x30)

        errorCode := div(errorCode, 10)
        let tenths := add(mod(errorCode, 10), 0x30)

        errorCode := div(errorCode, 10)
        let hundreds := add(mod(errorCode, 10), 0x30)


        let revertReason := shl(200, add(0x42414c23000000, add(add(units, shl(8, tenths)), shl(16, hundreds))))


        mstore(0x0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
        mstore(0x04, 0x0000000000000000000000000000000000000000000000000000000000000020)
        mstore(0x24, 7)
        mstore(0x44, revertReason)

        revert(0, 100)
    }
}

library Errors {

    uint256 internal constant ADD_OVERFLOW = 0;
    uint256 internal constant SUB_OVERFLOW = 1;
    uint256 internal constant SUB_UNDERFLOW = 2;
    uint256 internal constant MUL_OVERFLOW = 3;
    uint256 internal constant ZERO_DIVISION = 4;
    uint256 internal constant DIV_INTERNAL = 5;
    uint256 internal constant X_OUT_OF_BOUNDS = 6;
    uint256 internal constant Y_OUT_OF_BOUNDS = 7;
    uint256 internal constant PRODUCT_OUT_OF_BOUNDS = 8;
    uint256 internal constant INVALID_EXPONENT = 9;

    uint256 internal constant OUT_OF_BOUNDS = 100;
    uint256 internal constant UNSORTED_ARRAY = 101;
    uint256 internal constant UNSORTED_TOKENS = 102;
    uint256 internal constant INPUT_LENGTH_MISMATCH = 103;
    uint256 internal constant ZERO_TOKEN = 104;

    uint256 internal constant MIN_TOKENS = 200;
    uint256 internal constant MAX_TOKENS = 201;
    uint256 internal constant MAX_SWAP_FEE_PERCENTAGE = 202;
    uint256 internal constant MIN_SWAP_FEE_PERCENTAGE = 203;
    uint256 internal constant MINIMUM_BPT = 204;
    uint256 internal constant CALLER_NOT_VAULT = 205;
    uint256 internal constant UNINITIALIZED = 206;
    uint256 internal constant BPT_IN_MAX_AMOUNT = 207;
    uint256 internal constant BPT_OUT_MIN_AMOUNT = 208;
    uint256 internal constant EXPIRED_PERMIT = 209;
    uint256 internal constant NOT_TWO_TOKENS = 210;

    uint256 internal constant MIN_AMP = 300;
    uint256 internal constant MAX_AMP = 301;
    uint256 internal constant MIN_WEIGHT = 302;
    uint256 internal constant MAX_STABLE_TOKENS = 303;
    uint256 internal constant MAX_IN_RATIO = 304;
    uint256 internal constant MAX_OUT_RATIO = 305;
    uint256 internal constant MIN_BPT_IN_FOR_TOKEN_OUT = 306;
    uint256 internal constant MAX_OUT_BPT_FOR_TOKEN_IN = 307;
    uint256 internal constant NORMALIZED_WEIGHT_INVARIANT = 308;
    uint256 internal constant INVALID_TOKEN = 309;
    uint256 internal constant UNHANDLED_JOIN_KIND = 310;
    uint256 internal constant ZERO_INVARIANT = 311;
    uint256 internal constant ORACLE_INVALID_SECONDS_QUERY = 312;
    uint256 internal constant ORACLE_NOT_INITIALIZED = 313;
    uint256 internal constant ORACLE_QUERY_TOO_OLD = 314;
    uint256 internal constant ORACLE_INVALID_INDEX = 315;
    uint256 internal constant ORACLE_BAD_SECS = 316;
    uint256 internal constant AMP_END_TIME_TOO_CLOSE = 317;
    uint256 internal constant AMP_ONGOING_UPDATE = 318;
    uint256 internal constant AMP_RATE_TOO_HIGH = 319;
    uint256 internal constant AMP_NO_ONGOING_UPDATE = 320;
    uint256 internal constant STABLE_INVARIANT_DIDNT_CONVERGE = 321;
    uint256 internal constant STABLE_GET_BALANCE_DIDNT_CONVERGE = 322;
    uint256 internal constant RELAYER_NOT_CONTRACT = 323;
    uint256 internal constant BASE_POOL_RELAYER_NOT_CALLED = 324;
    uint256 internal constant REBALANCING_RELAYER_REENTERED = 325;
    uint256 internal constant GRADUAL_UPDATE_TIME_TRAVEL = 326;
    uint256 internal constant SWAPS_DISABLED = 327;
    uint256 internal constant CALLER_IS_NOT_LBP_OWNER = 328;
    uint256 internal constant PRICE_RATE_OVERFLOW = 329;
    uint256 internal constant INVALID_JOIN_EXIT_KIND_WHILE_SWAPS_DISABLED = 330;
    uint256 internal constant WEIGHT_CHANGE_TOO_FAST = 331;
    uint256 internal constant LOWER_GREATER_THAN_UPPER_TARGET = 332;
    uint256 internal constant UPPER_TARGET_TOO_HIGH = 333;
    uint256 internal constant UNHANDLED_BY_LINEAR_POOL = 334;
    uint256 internal constant OUT_OF_TARGET_RANGE = 335;

    uint256 internal constant REENTRANCY = 400;
    uint256 internal constant SENDER_NOT_ALLOWED = 401;
    uint256 internal constant PAUSED = 402;
    uint256 internal constant PAUSE_WINDOW_EXPIRED = 403;
    uint256 internal constant MAX_PAUSE_WINDOW_DURATION = 404;
    uint256 internal constant MAX_BUFFER_PERIOD_DURATION = 405;
    uint256 internal constant INSUFFICIENT_BALANCE = 406;
    uint256 internal constant INSUFFICIENT_ALLOWANCE = 407;
    uint256 internal constant ERC20_TRANSFER_FROM_ZERO_ADDRESS = 408;
    uint256 internal constant ERC20_TRANSFER_TO_ZERO_ADDRESS = 409;
    uint256 internal constant ERC20_MINT_TO_ZERO_ADDRESS = 410;
    uint256 internal constant ERC20_BURN_FROM_ZERO_ADDRESS = 411;
    uint256 internal constant ERC20_APPROVE_FROM_ZERO_ADDRESS = 412;
    uint256 internal constant ERC20_APPROVE_TO_ZERO_ADDRESS = 413;
    uint256 internal constant ERC20_TRANSFER_EXCEEDS_ALLOWANCE = 414;
    uint256 internal constant ERC20_DECREASED_ALLOWANCE_BELOW_ZERO = 415;
    uint256 internal constant ERC20_TRANSFER_EXCEEDS_BALANCE = 416;
    uint256 internal constant ERC20_BURN_EXCEEDS_ALLOWANCE = 417;
    uint256 internal constant SAFE_ERC20_CALL_FAILED = 418;
    uint256 internal constant ADDRESS_INSUFFICIENT_BALANCE = 419;
    uint256 internal constant ADDRESS_CANNOT_SEND_VALUE = 420;
    uint256 internal constant SAFE_CAST_VALUE_CANT_FIT_INT256 = 421;
    uint256 internal constant GRANT_SENDER_NOT_ADMIN = 422;
    uint256 internal constant REVOKE_SENDER_NOT_ADMIN = 423;
    uint256 internal constant RENOUNCE_SENDER_NOT_ALLOWED = 424;
    uint256 internal constant BUFFER_PERIOD_EXPIRED = 425;
    uint256 internal constant CALLER_IS_NOT_OWNER = 426;
    uint256 internal constant NEW_OWNER_IS_ZERO = 427;
    uint256 internal constant CODE_DEPLOYMENT_FAILED = 428;
    uint256 internal constant CALL_TO_NON_CONTRACT = 429;
    uint256 internal constant LOW_LEVEL_CALL_FAILED = 430;

    uint256 internal constant INVALID_POOL_ID = 500;
    uint256 internal constant CALLER_NOT_POOL = 501;
    uint256 internal constant SENDER_NOT_ASSET_MANAGER = 502;
    uint256 internal constant USER_DOESNT_ALLOW_RELAYER = 503;
    uint256 internal constant INVALID_SIGNATURE = 504;
    uint256 internal constant EXIT_BELOW_MIN = 505;
    uint256 internal constant JOIN_ABOVE_MAX = 506;
    uint256 internal constant SWAP_LIMIT = 507;
    uint256 internal constant SWAP_DEADLINE = 508;
    uint256 internal constant CANNOT_SWAP_SAME_TOKEN = 509;
    uint256 internal constant UNKNOWN_AMOUNT_IN_FIRST_SWAP = 510;
    uint256 internal constant MALCONSTRUCTED_MULTIHOP_SWAP = 511;
    uint256 internal constant INTERNAL_BALANCE_OVERFLOW = 512;
    uint256 internal constant INSUFFICIENT_INTERNAL_BALANCE = 513;
    uint256 internal constant INVALID_ETH_INTERNAL_BALANCE = 514;
    uint256 internal constant INVALID_POST_LOAN_BALANCE = 515;
    uint256 internal constant INSUFFICIENT_ETH = 516;
    uint256 internal constant UNALLOCATED_ETH = 517;
    uint256 internal constant ETH_TRANSFER = 518;
    uint256 internal constant CANNOT_USE_ETH_SENTINEL = 519;
    uint256 internal constant TOKENS_MISMATCH = 520;
    uint256 internal constant TOKEN_NOT_REGISTERED = 521;
    uint256 internal constant TOKEN_ALREADY_REGISTERED = 522;
    uint256 internal constant TOKENS_ALREADY_SET = 523;
    uint256 internal constant TOKENS_LENGTH_MUST_BE_2 = 524;
    uint256 internal constant NONZERO_TOKEN_BALANCE = 525;
    uint256 internal constant BALANCE_TOTAL_OVERFLOW = 526;
    uint256 internal constant POOL_NO_TOKENS = 527;
    uint256 internal constant INSUFFICIENT_FLASH_LOAN_BALANCE = 528;

    uint256 internal constant SWAP_FEE_PERCENTAGE_TOO_HIGH = 600;
    uint256 internal constant FLASH_LOAN_FEE_PERCENTAGE_TOO_HIGH = 601;
    uint256 internal constant INSUFFICIENT_FLASH_LOAN_FEE_AMOUNT = 602;
}// MIT

pragma solidity ^0.7.0;

interface IERC20 {

    function totalSupply() external view returns (uint256);


    function balanceOf(address account) external view returns (uint256);


    function transfer(address recipient, uint256 amount) external returns (bool);


    function allowance(address owner, address spender) external view returns (uint256);


    function approve(address spender, uint256 amount) external returns (bool);


    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}// MIT


pragma solidity ^0.7.0;



library SafeERC20 {

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {

        _callOptionalReturn(address(token), abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {

        _callOptionalReturn(address(token), abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function _callOptionalReturn(address token, bytes memory data) private {

        (bool success, bytes memory returndata) = token.call(data);

        assembly {
            if eq(success, 0) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }

        _require(returndata.length == 0 || abi.decode(returndata, (bool)), Errors.SAFE_ERC20_CALL_FAILED);
    }
}// MIT

pragma solidity ^0.7.0;


library SafeMath {

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        _require(c >= a, Errors.ADD_OVERFLOW);

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, Errors.SUB_OVERFLOW);
    }

    function sub(uint256 a, uint256 b, uint256 errorCode) internal pure returns (uint256) {

        _require(b <= a, errorCode);
        uint256 c = a - b;

        return c;
    }
}// MIT

pragma solidity ^0.7.0;



contract ERC20 is IERC20 {

    using SafeMath for uint256;

    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
        _decimals = 18;
    }

    function name() public view returns (string memory) {

        return _name;
    }

    function symbol() public view returns (string memory) {

        return _symbol;
    }

    function decimals() public view returns (uint8) {

        return _decimals;
    }

    function totalSupply() public view override returns (uint256) {

        return _totalSupply;
    }

    function balanceOf(address account) public view override returns (uint256) {

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
        _approve(
            sender,
            msg.sender,
            _allowances[sender][msg.sender].sub(amount, Errors.ERC20_TRANSFER_EXCEEDS_ALLOWANCE)
        );
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        _approve(msg.sender, spender, _allowances[msg.sender][spender].add(addedValue));
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        _approve(
            msg.sender,
            spender,
            _allowances[msg.sender][spender].sub(subtractedValue, Errors.ERC20_DECREASED_ALLOWANCE_BELOW_ZERO)
        );
        return true;
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {

        _require(sender != address(0), Errors.ERC20_TRANSFER_FROM_ZERO_ADDRESS);
        _require(recipient != address(0), Errors.ERC20_TRANSFER_TO_ZERO_ADDRESS);

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(amount, Errors.ERC20_TRANSFER_EXCEEDS_BALANCE);
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {

        _require(account != address(0), Errors.ERC20_BURN_FROM_ZERO_ADDRESS);

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(amount, Errors.ERC20_BURN_EXCEEDS_ALLOWANCE);
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual {

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _setupDecimals(uint8 decimals_) internal {

        _decimals = decimals_;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual {}

}// MIT

pragma solidity ^0.7.0;


abstract contract ERC20Burnable is ERC20 {
    using SafeMath for uint256;

    function burn(uint256 amount) public virtual {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) public virtual {
        uint256 decreasedAllowance = allowance(account, msg.sender).sub(amount, Errors.ERC20_BURN_EXCEEDS_ALLOWANCE);

        _approve(account, msg.sender, decreasedAllowance);
        _burn(account, amount);
    }
}// MIT

pragma solidity ^0.7.0;


library Address {
    function isContract(address account) internal view returns (bool) {

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        _require(address(this).balance >= amount, Errors.ADDRESS_INSUFFICIENT_BALANCE);

        (bool success, ) = recipient.call{ value: amount }("");
        _require(success, Errors.ADDRESS_CANNOT_SEND_VALUE);
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        _require(isContract(target), Errors.CALL_TO_NON_CONTRACT);

        (bool success, bytes memory returndata) = target.call(data);
        return verifyCallResult(success, returndata);
    }

    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            if (returndata.length > 0) {
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                _revert(Errors.LOW_LEVEL_CALL_FAILED);
            }
        }
    }
}// MIT

pragma solidity ^0.7.0;


library Math {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        _require(c >= a, Errors.ADD_OVERFLOW);
        return c;
    }

    function add(int256 a, int256 b) internal pure returns (int256) {
        int256 c = a + b;
        _require((b >= 0 && c >= a) || (b < 0 && c < a), Errors.ADD_OVERFLOW);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        _require(b <= a, Errors.SUB_OVERFLOW);
        uint256 c = a - b;
        return c;
    }

    function sub(int256 a, int256 b) internal pure returns (int256) {
        int256 c = a - b;
        _require((b >= 0 && c <= a) || (b < 0 && c > a), Errors.SUB_OVERFLOW);
        return c;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        _require(a == 0 || c / a == b, Errors.MUL_OVERFLOW);
        return c;
    }

    function div(
        uint256 a,
        uint256 b,
        bool roundUp
    ) internal pure returns (uint256) {
        return roundUp ? divUp(a, b) : divDown(a, b);
    }

    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        _require(b != 0, Errors.ZERO_DIVISION);
        return a / b;
    }

    function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        _require(b != 0, Errors.ZERO_DIVISION);

        if (a == 0) {
            return 0;
        } else {
            return 1 + (a - 1) / b;
        }
    }
}// MIT


pragma solidity ^0.7.0;


abstract contract ReentrancyGuard {

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        _enterNonReentrant();
        _;
        _exitNonReentrant();
    }

    function _enterNonReentrant() private {
        _require(_status != _ENTERED, Errors.REENTRANCY);

        _status = _ENTERED;
    }

    function _exitNonReentrant() private {
        _status = _NOT_ENTERED;
    }
}// NONE
pragma solidity 0.7.6;


contract Distribute is Ownable, ReentrancyGuard {
    using Math for uint256;
    using SafeERC20 for IERC20;

    uint256 immutable public PRECISION;

    uint256 public constant INITIAL_BOND_VALUE = 1000000;

    uint256 public bond_value = INITIAL_BOND_VALUE;
    uint256 public investor_count;

    uint256 private _total_staked;
    uint256 private _temp_pool;
    uint256 public to_distribute;
    mapping(address => uint256) private _bond_value_addr;
    mapping(address => uint256) private _stakes;

    IERC20 immutable public reward_token;

    constructor(uint256 decimals, IERC20 _reward_token) Ownable() ReentrancyGuard() {
        reward_token = _reward_token;
        PRECISION = 10**decimals;
    }

    function stakeFor(address account, uint256 amount) public onlyOwner nonReentrant {
        require(account != address(0), "Distribute: Invalid account");
        require(amount > 0, "Distribute: Amount must be greater than zero");
        _total_staked = _total_staked.add(amount);
        if(_stakes[account] == 0) {
            investor_count++;
        }
        uint256 accumulated_reward = getReward(account);
        _stakes[account] = _stakes[account].add(amount);

        uint256 new_bond_value = accumulated_reward * PRECISION / _stakes[account];
        _bond_value_addr[account] = bond_value - new_bond_value;
    }

    function unstakeFrom(address payable account, uint256 amount) public onlyOwner nonReentrant {
        require(account != address(0), "Distribute: Invalid account");
        require(amount > 0, "Distribute: Amount must be greater than zero");
        require(amount <= _stakes[account], "Distribute: Dont have enough staked");
        uint256 to_reward = _getReward(account, amount);
        _total_staked -= amount;
        _stakes[account] -= amount;
        if(_stakes[account] == 0) {
            investor_count--;
        }

        if(to_reward == 0) return;
        if(address(reward_token) != address(0)) {
            reward_token.safeTransfer(account, to_reward);
        }
        else {
            Address.sendValue(account, to_reward);
        }
    }

    function withdrawFrom(address payable account, uint256 amount) external onlyOwner {
        unstakeFrom(account, amount);
        stakeFor(account, amount);
    }

    function distribute(uint256 amount, address from) external payable onlyOwner nonReentrant {
        if(address(reward_token) != address(0)) {
            if(amount == 0) return;
            reward_token.safeTransferFrom(from, address(this), amount);
            require(msg.value == 0, "Distribute: Illegal distribution");
        } else {
            amount = msg.value;
        }

        uint256 total_bonds = _total_staked / PRECISION;

        if(total_bonds == 0) {
            _temp_pool = _temp_pool.add(amount);
            return;
        }

        if(_temp_pool > 0) {
            amount = amount.add(_temp_pool);
            _temp_pool = 0;
        }
        
        uint256 temp_to_distribute = to_distribute + amount;
        uint256 bond_increase = temp_to_distribute / total_bonds;
        uint256 distributed_total = total_bonds.mul(bond_increase);
        bond_value += bond_increase;
        
        to_distribute = temp_to_distribute - distributed_total;
    }

    function totalStakedFor(address account) external view returns (uint256) {
        return _stakes[account];
    }
    
    function totalStaked() external view returns (uint256) {
        return _total_staked;
    }

    function getReward(address account) public view returns (uint256) {
        return _getReward(account,_stakes[account]);
    }

    function getTotalReward() external view returns (uint256) {
        if(address(reward_token) != address(0)) {
            return reward_token.balanceOf(address(this));
        } else {
            return address(this).balance;
        }
    }

    function _getReward(address account, uint256 amount) internal view returns (uint256) {
        return amount.mul(bond_value.sub(_bond_value_addr[account])) / PRECISION;
    }
}// NONE
pragma solidity 0.7.6;

interface IStakingERC20  {
    function staking_contract_token() external returns (address);
    function distribute_eth() payable external;
    function distribute(uint256 amount) external;
    function stake(uint256 amount, bytes calldata data) external;
    function stakeFor(address account, uint256 amount, bytes calldata data) external;
    function unstake(uint256 amount, bytes calldata data) external;
    function withdraw(uint256 amount) external;
    function totalStakedFor(address account) external view returns (uint256);
    function totalStaked() external view returns (uint256);
    function token() external view returns (address);
    function supportsHistory() external pure returns (bool);
    function getReward(address account) external view returns (uint256 _eth, uint256 _token);
}// NONE
pragma solidity 0.7.6;



contract EEFIToken is ERC20Burnable, Ownable {
    constructor() 
    ERC20("Amplesense Elastic Finance token", "EEFI")
    Ownable() {
    }

    function mint(address account, uint256 amount) public onlyOwner {
        _mint(account, amount);
    }
}// MIT


pragma solidity ^0.7.0;


library EnumerableSet {

    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes;
    }

    function add(AddressSet storage set, address value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function remove(AddressSet storage set, address value) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) {

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            if (toDeleteIndex != lastIndex) {
                address lastValue = set._values[lastIndex];

                set._values[toDeleteIndex] = lastValue;
                set._indexes[lastValue] = toDeleteIndex + 1; // All indexes are 1-based
            }

            set._values.pop();

            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        _require(set._values.length > index, Errors.OUT_OF_BOUNDS);
        return unchecked_at(set, index);
    }

    function unchecked_at(AddressSet storage set, uint256 index) internal view returns (address) {
        return set._values[index];
    }

    function rawIndexOf(AddressSet storage set, address value) internal view returns (uint256) {
        return set._indexes[value] - 1;
    }
}// MIT

pragma solidity ^0.7.0;



abstract contract AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct RoleData {
        EnumerableSet.AddressSet members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
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
        _require(hasRole(_roles[role].adminRole, msg.sender), Errors.GRANT_SENDER_NOT_ADMIN);

        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual {
        _require(hasRole(_roles[role].adminRole, msg.sender), Errors.REVOKE_SENDER_NOT_ADMIN);

        _revokeRole(role, account);
    }

    function renounceRole(bytes32 role, address account) public virtual {
        _require(account == msg.sender, Errors.RENOUNCE_SENDER_NOT_ALLOWED);

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
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (_roles[role].members.remove(account)) {
            emit RoleRevoked(role, account, msg.sender);
        }
    }
}// NONE
pragma solidity 0.7.6;


abstract contract AMPLRebaser is AccessControl {

    event Rebase(uint256 old_supply, uint256 new_supply);

    bytes32 public constant REBASER_ROLE = keccak256("REBASER_ROLE");

    uint256 public last_ampl_supply;

    uint256 public last_rebase_call;

    IERC20 immutable public ampl_token;

    constructor(IERC20 _ampl_token) {
        require(address(_ampl_token) != address(0), "AMPLRebaser: Invalid ampl token address");
        ampl_token = _ampl_token;
        last_ampl_supply = _ampl_token.totalSupply();
        last_rebase_call = block.timestamp;

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(REBASER_ROLE, msg.sender);
        _setRoleAdmin(REBASER_ROLE, DEFAULT_ADMIN_ROLE);
    }

    function rebase(uint256 minimalExpectedEEFI, uint256 minimalExpectedETH) external {
        require(hasRole(REBASER_ROLE, msg.sender), "AMPLRebaser: rebase can only be called by the REBASE manager");
        require(block.timestamp - 24 hours > last_rebase_call, "AMPLRebaser: rebase can only be called once every 24 hours");
        last_rebase_call = block.timestamp;
        uint256 new_supply = ampl_token.totalSupply();
        _rebase(last_ampl_supply, new_supply, minimalExpectedEEFI, minimalExpectedETH);
        emit Rebase(last_ampl_supply, new_supply);
        last_ampl_supply = new_supply;
    }

    function _rebase(uint256 old_supply, uint256 new_supply, uint256 minimalExpectedEEFI, uint256 minimalExpectedETH) internal virtual;
}// NONE
pragma solidity 0.7.6;

interface IBalancerTrader {
    event Sale_EEFI(uint256 ampl_amount, uint256 eefi_amount);
    event Sale_ETH(uint256 ampl_amount, uint256 eth_amount);

    function sellAMPLForEth(uint256 amount, uint256 minimalExpectedAmount) external returns (uint256);
    function sellAMPLForEEFI(uint256 amount, uint256 minimalExpectedAmount) external returns (uint256);
}// NONE
pragma solidity 0.7.6;



contract AmplesenseVault is AMPLRebaser, Ownable {
    using SafeERC20 for IERC20;
    using Math for uint256;

    IStakingERC20 public pioneer_vault1;
    IStakingERC20 public pioneer_vault2;
    IStakingERC20 public pioneer_vault3;
    IStakingERC20 public staking_pool;
    IBalancerTrader public trader;
    EEFIToken public eefi_token;
    Distribute immutable public rewards_eefi;
    Distribute immutable public rewards_eth;
    address payable treasury;
    uint256 public last_positive = block.timestamp;

    uint256 constant public EEFI_DEPOSIT_RATE = 10000;
    uint256 constant public EEFI_NEGATIVE_REBASE_RATE = 100000;
    uint256 constant public EEFI_EQULIBRIUM_REBASE_RATE = 10000;
    uint256 constant public DEPOSIT_FEE_10000 = 65;
    uint256 constant public LOCK_TIME = 90 days;
    uint256 constant public TRADE_POSITIVE_EEFI_100 = 48;
    uint256 constant public TRADE_POSITIVE_ETH_100 = 20;
    uint256 constant public TRADE_POSITIVE_PIONEER1_100 = 2;
    uint256 constant public TRADE_POSITIVE_REWARDS_100 = 45;
    uint256 constant public TRADE_POSITIVE_PIONEER2_100 = 10;
    uint256 constant public TRADE_POSITIVE_PIONEER3_100 = 5;
    uint256 constant public TRADE_POSITIVE_LPSTAKING_100 = 35;
    uint256 constant public TREASURY_EEFI_100 = 10;
    uint256 constant public MINTING_DECAY = 90 days;
    uint256 constant public INITIAL_MINT = 100000 ether;


    event Burn(uint256 amount);
    event Claimed(address indexed account, uint256 eth, uint256 token);
    event Deposit(address indexed account, uint256 amount, uint256 length);
    event Withdrawal(address indexed account, uint256 amount, uint256 length);
    event StakeChanged(uint256 total, uint256 timestamp);

    struct DepositChunk {
        uint256 amount;
        uint256 timestamp;
    }

    mapping(address => DepositChunk[]) private _deposits;
    
    constructor(IERC20 ampl_token)
    AMPLRebaser(ampl_token)
    Ownable() {
        eefi_token = new EEFIToken();
        rewards_eefi = new Distribute(9, IERC20(eefi_token));
        rewards_eth = new Distribute(9, IERC20(0));
    }

    receive() external payable { }



    function totalStakedFor(address account) public view returns (uint256 total) {
        for(uint i = 0; i < _deposits[account].length; i++) {
            total += _deposits[account][i].amount;
        }
        return total;
    }

    function totalClaimableBy(address account) public view returns (uint256 total) {
        if(rewards_eefi.totalStaked() == 0) return 0;
        uint256 ampl_balance = ampl_token.balanceOf(address(this));
        for(uint i = 0; i < _deposits[account].length; i++) {
            if(_deposits[account][i].timestamp < block.timestamp.sub(LOCK_TIME)) {
                total += _deposits[account][i].amount;
            }
        }
        return ampl_balance.mul(total).divDown(rewards_eefi.totalStaked());
    }

    function balanceOf(address account) public view returns(uint256 ampl) {
        if(rewards_eefi.totalStaked() == 0) return 0;
        uint256 ampl_balance = ampl_token.balanceOf(address(this));
        ampl = ampl_balance.mul(rewards_eefi.totalStakedFor(account)).divDown(rewards_eefi.totalStaked());
    }

    function initialize(IStakingERC20 _pioneer_vault1, IStakingERC20 _pioneer_vault2, IStakingERC20 _pioneer_vault3, IStakingERC20 _staking_pool, address payable _treasury) external
    onlyOwner() 
    {
        require(address(pioneer_vault1) == address(0), "AmplesenseVault: contract already initialized");
        pioneer_vault1 = _pioneer_vault1;
        pioneer_vault2 = _pioneer_vault2;
        pioneer_vault3 = _pioneer_vault3;
        staking_pool = _staking_pool;
        treasury = _treasury;
        eefi_token.mint(treasury, INITIAL_MINT);
    }

    function setTrader(IBalancerTrader _trader) external onlyOwner() {
        require(address(_trader) != address(0), "AmplesenseVault: invalid trader");
        trader = _trader;
    }

    function makeDeposit(uint256 amount) external {
        ampl_token.safeTransferFrom(msg.sender, address(this), amount);
        _deposits[msg.sender].push(DepositChunk(amount, block.timestamp));

        uint256 to_mint = amount / EEFI_DEPOSIT_RATE * 10**9;
        uint256 deposit_fee = to_mint.mul(DEPOSIT_FEE_10000).divDown(10000);
        if(last_positive + MINTING_DECAY > block.timestamp) { // if 90 days without positive rebase do not mint EEFI
            eefi_token.mint(address(this), deposit_fee);
            eefi_token.increaseAllowance(pioneer_vault2.staking_contract_token(), deposit_fee);
            pioneer_vault2.distribute(deposit_fee);
            eefi_token.mint(msg.sender, to_mint.sub(deposit_fee));
        }
        
        rewards_eefi.stakeFor(msg.sender, amount);
        rewards_eth.stakeFor(msg.sender, amount);
        emit Deposit(msg.sender, amount, _deposits[msg.sender].length);
        emit StakeChanged(rewards_eth.totalStaked(), block.timestamp);
    }

    function withdrawAMPL(uint256 amount, uint256 minimalExpectedAmount) external {
        require(minimalExpectedAmount > 0, "AmplesenseVault: Minimal expected amount must be higher than zero");
        uint256 amplBalance = ampl_token.balanceOf(address(this));
        uint256 totalStaked = rewards_eefi.totalStaked();
        uint256 shares = amount.mul(totalStaked).divDown(amplBalance);
        uint256 minimalShares = minimalExpectedAmount.mul(totalStaked).divDown(amplBalance);

        require(minimalShares <= totalStakedFor(msg.sender), "AmplesenseVault: Not enough balance");
        uint256 to_withdraw = shares;
        while(to_withdraw > 0) {
            DepositChunk storage deposit = _deposits[msg.sender][0];
            if(deposit.timestamp > block.timestamp.sub(LOCK_TIME)) {
                require(to_withdraw <= shares.sub(minimalShares), "AmplesenseVault: No unlocked deposits found");
                break; // exit the loop
            }
            if(deposit.amount > to_withdraw) {
                deposit.amount = deposit.amount.sub(to_withdraw);
                to_withdraw = 0;
            } else {
                to_withdraw = to_withdraw.sub(deposit.amount);
                _popDeposit();
            }
        }
        uint256 amountOfSharesWithdrawn = shares.sub(to_withdraw);
        uint256 ampl_amount = amplBalance.mul(amountOfSharesWithdrawn).divDown(rewards_eefi.totalStaked());
        ampl_token.safeTransfer(msg.sender, ampl_amount);
        
        rewards_eefi.unstakeFrom(msg.sender, amountOfSharesWithdrawn);
        rewards_eth.unstakeFrom(msg.sender, amountOfSharesWithdrawn);
        emit Withdrawal(msg.sender, ampl_amount,_deposits[msg.sender].length);
        emit StakeChanged(rewards_eth.totalStaked(), block.timestamp);
    }

    function withdraw(uint256 amount) public {
        require(amount <= totalStakedFor(msg.sender), "AmplesenseVault: Not enough balance");
        uint256 to_withdraw = amount;
        while(to_withdraw > 0) {
            DepositChunk storage deposit = _deposits[msg.sender][0];
            require(deposit.timestamp < block.timestamp.sub(LOCK_TIME), "AmplesenseVault: No unlocked deposits found");
            if(deposit.amount > to_withdraw) {
                deposit.amount = deposit.amount.sub(to_withdraw);
                to_withdraw = 0;
            } else {
                to_withdraw = to_withdraw.sub(deposit.amount);
                _popDeposit();
            }
        }
        uint256 ampl_amount = ampl_token.balanceOf(address(this)).mul(amount).divDown(rewards_eefi.totalStaked());
        ampl_token.safeTransfer(msg.sender, ampl_amount);
        
        rewards_eefi.unstakeFrom(msg.sender, amount);
        rewards_eth.unstakeFrom(msg.sender, amount);
        emit Withdrawal(msg.sender, ampl_amount,_deposits[msg.sender].length);
        emit StakeChanged(rewards_eth.totalStaked(), block.timestamp);
    }
    function _rebase(uint256 old_supply, uint256 new_supply, uint256 minimalExpectedEEFI, uint256 minimalExpectedETH) internal override {
        uint256 new_balance = ampl_token.balanceOf(address(this));

        if(new_supply > old_supply) {
            last_positive = block.timestamp;
            require(address(trader) != address(0), "AmplesenseVault: trader not set");

            uint256 changeRatio18Digits = old_supply.mul(10**18).divDown(new_supply);
            uint256 surplus = new_balance.sub(new_balance.mul(changeRatio18Digits).divDown(10**18));

            uint256 for_eefi = surplus.mul(TRADE_POSITIVE_EEFI_100).divDown(100);
            uint256 for_eth = surplus.mul(TRADE_POSITIVE_ETH_100).divDown(100);
            uint256 for_pioneer1 = surplus.mul(TRADE_POSITIVE_PIONEER1_100).divDown(100);

            
            ampl_token.approve(address(trader), for_eefi.add(for_eth));

            trader.sellAMPLForEEFI(for_eefi, minimalExpectedEEFI);

            uint256 balance = eefi_token.balanceOf(address(this));
            IERC20(address(eefi_token)).safeTransfer(treasury, balance.mul(TREASURY_EEFI_100).divDown(100));
            uint256 to_burn = eefi_token.balanceOf(address(this));
            eefi_token.burn(to_burn);
            emit Burn(to_burn);
            trader.sellAMPLForEth(for_eth, minimalExpectedETH);
 
            uint256 to_rewards = address(this).balance.mul(TRADE_POSITIVE_REWARDS_100).divDown(100);
            uint256 to_pioneer2 = address(this).balance.mul(TRADE_POSITIVE_PIONEER2_100).divDown(100);
            uint256 to_pioneer3 = address(this).balance.mul(TRADE_POSITIVE_PIONEER3_100).divDown(100);
            uint256 to_lp_staking = address(this).balance.mul(TRADE_POSITIVE_LPSTAKING_100).divDown(100);
            
            rewards_eth.distribute{value: to_rewards}(to_rewards, address(this));
            pioneer_vault2.distribute_eth{value: to_pioneer2}();
            pioneer_vault3.distribute_eth{value: to_pioneer3}();
            staking_pool.distribute_eth{value: to_lp_staking}();

            ampl_token.approve(address(pioneer_vault1), for_pioneer1);
            pioneer_vault1.distribute(for_pioneer1);

            Address.sendValue(treasury, address(this).balance);
        } else {
            if(last_positive + MINTING_DECAY > block.timestamp) { //if 90 days without positive rebase do not mint
                uint256 to_mint = new_balance.divDown(new_supply < last_ampl_supply ? EEFI_NEGATIVE_REBASE_RATE : EEFI_EQULIBRIUM_REBASE_RATE) * 10**9; /*multiplying by 10^9 because EEFI is 18 digits and not 9*/
                eefi_token.mint(address(this), to_mint);



                uint256 to_rewards = to_mint.mul(TRADE_POSITIVE_REWARDS_100).divDown(100);
                uint256 to_pioneer2 = to_mint.mul(TRADE_POSITIVE_PIONEER2_100).divDown(100);
                uint256 to_pioneer3 = to_mint.mul(TRADE_POSITIVE_PIONEER3_100).divDown(100);
                uint256 to_lp_staking = to_mint.mul(TRADE_POSITIVE_LPSTAKING_100).divDown(100);

                eefi_token.increaseAllowance(address(rewards_eefi), to_rewards);
                eefi_token.increaseAllowance(address(pioneer_vault2.staking_contract_token()), to_pioneer2);
                eefi_token.increaseAllowance(address(pioneer_vault3.staking_contract_token()), to_pioneer3);
                eefi_token.increaseAllowance(address(staking_pool.staking_contract_token()), to_lp_staking);

                rewards_eefi.distribute(to_rewards, address(this));
                pioneer_vault2.distribute(to_pioneer2);
                pioneer_vault3.distribute(to_pioneer3);
                staking_pool.distribute(to_lp_staking);

                IERC20(eefi_token).safeTransfer(treasury, eefi_token.balanceOf(address(this)));
            }
        }
    }

    function claim() external {
        (uint256 eth, uint256 token) = getReward(msg.sender);
        rewards_eth.withdrawFrom(msg.sender, rewards_eth.totalStakedFor(msg.sender));
        rewards_eefi.withdrawFrom(msg.sender, rewards_eefi.totalStakedFor(msg.sender));
        emit Claimed(msg.sender, eth, token);
    }

    function getReward(address account) public view returns (uint256 eth, uint256 token) {
        eth = rewards_eth.getReward(account);
        token = rewards_eefi.getReward(account);
    }

    function totalStaked() external view returns (uint256) {
        return rewards_eth.totalStaked();
    }

    function totalReward() external view returns (uint256 token, uint256 eth) {
        token = rewards_eefi.getTotalReward();
        eth = rewards_eth.getTotalReward();
    }

    function _popDeposit() internal {
        for (uint i = 0; i < _deposits[msg.sender].length - 1; i++) {
            _deposits[msg.sender][i] = _deposits[msg.sender][i + 1];
        }
        _deposits[msg.sender].pop();
    }
}