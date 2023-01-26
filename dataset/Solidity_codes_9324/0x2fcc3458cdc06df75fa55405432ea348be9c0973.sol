

pragma solidity ^0.6.6;

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

interface IERC20 {

  function totalSupply() external view returns (uint256);


  function balanceOf(address account) external view returns (uint256);


  function transfer(address recipient, uint256 amount) external returns (bool);


  function allowance(address owner, address spender)
    external
    view
    returns (uint256);


  function approve(address spender, uint256 amount) external returns (bool);


  function transferFrom(
    address sender,
    address recipient,
    uint256 amount
  ) external returns (bool);


  event Transfer(address indexed from, address indexed to, uint256 value);

  event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IUniswapV2Factory {

    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);

    function feeToSetter() external view returns (address);


    function getPair(address tokenA, address tokenB) external view returns (address pair);

    function allPairs(uint) external view returns (address pair);

    function allPairsLength() external view returns (uint);


    function createPair(address tokenA, address tokenB) external returns (address pair);


    function setFeeTo(address) external;

    function setFeeToSetter(address) external;

}

interface UniswapV2Router{

    
    function addLiquidity(
      address tokenA,
      address tokenB,
      uint amountADesired,
      uint amountBDesired,
      uint amountAMin,
      uint amountBMin,
      address to,
      uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);

    
    function addLiquidityETH(
      address token,
      uint amountTokenDesired,
      uint amountTokenMin,
      uint amountETHMin,
      address to,
      uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);

     
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);

    
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);

    
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);

    
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);


}

library UniswapV2Library {

    using SafeMath for uint;

    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {

        require(tokenA != tokenB, 'UniswapV2Library: IDENTICAL_ADDRESSES');
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), 'UniswapV2Library: ZERO_ADDRESS');
    }

    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {

        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(uint(keccak256(abi.encodePacked(
                hex'ff',
                factory,
                keccak256(abi.encodePacked(token0, token1)),
                hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f' // init code hash
            ))));
    }

    function getReserves(address factory, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {

        (address token0,) = sortTokens(tokenA, tokenB);
        (uint reserve0, uint reserve1,) = IUniswapV2Pair(pairFor(factory, tokenA, tokenB)).getReserves();
        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
    }

    function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {

        require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');
        require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        amountB = amountA.mul(reserveB) / reserveA;
    }

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {

        require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint amountInWithFee = amountIn.mul(997);
        uint numerator = amountInWithFee.mul(reserveOut);
        uint denominator = reserveIn.mul(1000).add(amountInWithFee);
        amountOut = numerator / denominator;
    }

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {

        require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint numerator = reserveIn.mul(amountOut).mul(1000);
        uint denominator = reserveOut.sub(amountOut).mul(997);
        amountIn = (numerator / denominator).add(1);
    }

    function getAmountsOut(address factory, uint amountIn, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[0] = amountIn;
        for (uint i; i < path.length - 1; i++) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i], path[i + 1]);
            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);
        }
    }

    function getAmountsIn(address factory, uint amountOut, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[amounts.length - 1] = amountOut;
        for (uint i = path.length - 1; i > 0; i--) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i - 1], path[i]);
            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);
        }
    }
}

interface IUniswapV2Pair {

    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);

    function symbol() external pure returns (string memory);

    function decimals() external pure returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);


    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);


    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function PERMIT_TYPEHASH() external pure returns (bytes32);

    function nonces(address owner) external view returns (uint);


    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;


    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to);
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);

    function factory() external view returns (address);

    function token0() external view returns (address);

    function token1() external view returns (address);

    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);

    function price0CumulativeLast() external view returns (uint);

    function price1CumulativeLast() external view returns (uint);

    function kLast() external view returns (uint);


    function mint(address to) external returns (uint liquidity);

    function burn(address to) external returns (uint amount0, uint amount1);

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;

    function skim(address to) external;

    function sync() external;


    function initialize(address, address) external;

}

library Address {

    function isContract(address account) internal view returns (bool) {


        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}

contract Owned {

    
    address public owner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    constructor(address _owner) public {
        owner = _owner;
    }

    modifier onlyOwner {

        require(msg.sender == owner, 'only owner allowed');
        _;
    }

    function transferOwnership(address _newOwner) external onlyOwner {

        owner = _newOwner;
        emit OwnershipTransferred(owner, _newOwner);
    }
}

interface Multiplier {

    function updateLockupPeriod(address _user, uint _lockup) external returns(bool);

    function getMultiplierCeiling() external pure returns (uint);

    function balance(address user) external view returns (uint);

    function approvedContract(address _user) external view returns(address);

    function lockupPeriod(address user) external view returns (uint);

}

contract PoolStake is Owned {

    using SafeMath for uint;
    
    IERC20 internal weth;                       //represents weth.
    IERC20 internal token;                      //represents the project's token which should have a weth pair on uniswap
    IERC20 internal lpToken;                    //lpToken for liquidity provisioning
    
    address internal uToken1;                   //utility token
    address internal uToken2;                   //utility token for migration 
    address internal platformWallet;            //fee receiver
    uint internal scalar = 10**36;              //unit for scaling
    uint internal cap;                          //ETH limit that can be provided
    bool internal migratedToLQDY;
    
    Multiplier internal multiplier1;                        //Interface of Multiplier contract
    Multiplier internal multiplier2;                        //Interface of Multiplier contract
    UniswapV2Router internal uniswapRouter;                 //Interface of Uniswap V2 router
    IUniswapV2Factory internal iUniswapV2Factory;           //Interface of uniswap V2 factory
    
    struct User {
        uint start;                 //starting period
        uint release;               //release period
        uint tokenBonus;            //user token bonus
        uint wethBonus;             //user weth bonus
        uint tokenWithdrawn;        //amount of token bonus withdrawn
        uint wethWithdrawn;         //amount of weth bonus withdrawn
        uint liquidity;             //user liquidity gotten from uniswap
        uint period;                //identifies users' current term period
        bool migrated;              //if migrated to uniswap V3
        uint lastAction;            //timestamp for user's last action
        uint lastTokenProvided;     //last provided token
        uint lastWethProvided;      //last provided eth
        uint lastTerm;              //last term joined
        uint lastPercentToken;      //last percentage for rewards token
        uint lastPercentWeth;       //last percentage for rewards eth
        bool multiplier;            //if last action included multiplier
    }
    
    mapping(address => User) internal _users;
    
    uint32 internal period1;
    uint32 internal period2;
    uint32 internal period3;
    uint32 internal period4;
    
    uint32 internal constant _012_HOURS_IN_SECONDS = 43200;
    
    mapping(uint => uint) internal _providers;
    
    uint internal period1RPWeth; 
    uint internal period2RPWeth;
    uint internal period3RPWeth;
    uint internal period4RPWeth;
    uint internal period1RPToken; 
    uint internal period2RPToken;
    uint internal period3RPToken;
    uint internal period4RPToken;
    
    uint internal _pendingBonusesWeth;
    uint internal _pendingBonusesToken;
    
    uint internal totalETHProvided;
    uint internal totalTokenProvided;
    uint internal totalProviders;
    
    address public migrationContract;
    
    event BonusAdded(address indexed sender, uint ethAmount, uint tokenAmount);
    event BonusRemoved(address indexed sender, uint amount);
    event CapUpdated(address indexed sender, uint amount);
    event LPWithdrawn(address indexed sender, uint amount);
    event LiquidityAdded(address indexed sender, uint liquidity, uint amountETH, uint amountToken);
    event LiquidityWithdrawn(address indexed sender, uint liquidity, uint amountETH, uint amountToken);
    event MigratedToLQDY(address indexed sender, address uToken, address multiplier);
    event FeeReceiverUpdated(address oldFeeReceiver, address newFeeReceiver);
    event NewUToken(address indexed sender, address uToken2, address multiplier);
    event UserTokenBonusWithdrawn(address indexed sender, uint amount, uint fee);
    event UserETHBonusWithdrawn(address indexed sender, uint amount, uint fee);
    event VersionMigrated(address indexed sender, uint256 time, address to);
    event LiquidityMigrated(address indexed sender, uint amount, address to);
    event StakeEnded(address indexed sender, uint lostETHBonus, uint lostTokenBonus);
    
    constructor(address _token, address _Owner) public Owned(_Owner) {
            
        require(_token != address(0), "can not deploy a zero address");
        token = IERC20(_token);
        weth = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2); 
        
        iUniswapV2Factory = IUniswapV2Factory(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);
        address _lpToken = iUniswapV2Factory.getPair(address(token), address(weth));
        require(_lpToken != address(0), "Pair must first be created on uniswap");
        lpToken = IERC20(_lpToken);
        
        uToken1 = 0x9Ed8e7C9604790F7Ec589F99b94361d8AAB64E5E;
        platformWallet = 0xa7A4d919202DFA2f4E44FFAc422d21095bF9770a;
        multiplier1 = Multiplier(0xbc962d7be33d8AfB4a547936D8CE6b9a1034E9EE);
        uniswapRouter = UniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    }
    
    modifier onlyPlatformWallet() {

        
        require(msg.sender == platformWallet, "only wallet can call");
        _;
    }
    
    modifier uTokenVet(uint _id) {

        
        if(uToken2 == address(0)) require(_id == 1, "currently accepts only uToken1");
        if(migratedToLQDY) require(_id != 1, "currently accepts only uToken2");
        _;
    }

    function newUToken(address _uToken2, address _multiplier2) external onlyPlatformWallet returns(bool) {

        
        require(uToken2 == address(0) && address(multiplier2) == address(0), "already migrated to LQDY");
        require(_uToken2 != address(0x0) && _multiplier2 != address(0x0), "cannot set the zero address");
        require(Address.isContract(_multiplier2), "multiplier must be a smart contract address");
        
        uToken2 = _uToken2;
        multiplier2 = Multiplier(_multiplier2);
        
        emit NewUToken(msg.sender, _uToken2, _multiplier2);
        return true;
    }
    
    function completeUTokenMerge() external onlyPlatformWallet returns(bool) {

        
        require(!migratedToLQDY, "already migrated to LQDY");
        
        migratedToLQDY = true;
        uToken1 = uToken2;
        
        address _multiplier2 = address(multiplier2);
        multiplier1 = Multiplier(_multiplier2);
        
        emit MigratedToLQDY(msg.sender, uToken2, address(multiplier2));
        return true;
    }
    
    function changeFeeReceiver(address _feeReceiver) external onlyPlatformWallet returns(bool) {

        
        platformWallet = _feeReceiver;
        
        emit FeeReceiverUpdated(msg.sender, _feeReceiver);
        return true;
    }
    
    function changeReturnPercentages(
        uint _period1RPETH, uint _period2RPETH, uint _period3RPETH, uint _period4RPETH, 
        uint _period1RPToken, uint _period2RPToken, uint _period3RPToken, uint _period4RPToken
    ) external onlyOwner returns(bool) {

        
        period1RPWeth = _period1RPETH;
        period2RPWeth = _period2RPETH;
        period3RPWeth = _period3RPETH;
        period4RPWeth = _period4RPETH;
        
        period1RPToken = _period1RPToken;
        period2RPToken = _period2RPToken;
        period3RPToken = _period3RPToken;
        period4RPToken = _period4RPToken;
        
        return true;
    }
    
    function changeTermPeriods(
        uint32 _firstTerm, uint32 _secondTerm, 
        uint32 _thirdTerm, uint32 _fourthTerm
    ) external onlyOwner returns(bool) {

        
        period1 = _firstTerm;
        period2 = _secondTerm;
        period3 = _thirdTerm;
        period4 = _fourthTerm;
        
        return true;
    }
    
    function changeCap(uint _cap) external onlyOwner returns(bool) {

        
        cap = _cap;
        
        emit CapUpdated(msg.sender, _cap);
        return true;
    }
    
    function allowMigration(address _unistakeMigrationContract) external onlyOwner returns (bool) {

        
        require(_unistakeMigrationContract != address(0x0), "cannot migrate to a null address");
        migrationContract = _unistakeMigrationContract;
        
        emit VersionMigrated(msg.sender, now, migrationContract);
        return true;
    }
    
    function startMigration(address _unistakeMigrationContract) external returns (bool) {

        
        require(_unistakeMigrationContract != address(0x0), "cannot migrate to a null address");
        require(migrationContract == _unistakeMigrationContract, "must confirm endpoint");
        require(!getUserMigration(msg.sender), "must not be migrated already");
        
        _users[msg.sender].migrated = true;
        
        uint256 liquidity = _users[msg.sender].liquidity;
        lpToken.transfer(migrationContract, liquidity);
        
        emit LiquidityMigrated(msg.sender, liquidity, migrationContract);
        return true;
    }
    
    function addBonus(uint _tokenAmount) external payable returns(bool) {

        
        require(_tokenAmount > 0 || msg.value > 0, "must send value");
        if (_tokenAmount > 0)
        require(token.transferFrom(msg.sender, address(this), _tokenAmount), "must approve smart contract");
        
        emit BonusAdded(msg.sender, msg.value, _tokenAmount);
        return true;
    }
    
    function removeETHAndTokenBouses(uint _amountETH, uint _amountToken) external onlyOwner returns (bool success) {

       
        require(_amountETH > 0 || _amountToken > 0, "amount must be larger than zero");
    
        if (_amountETH > 0) {
            require(_checkForSufficientStakingBonusesForETH(_amountETH), 'cannot withdraw above current ETH bonus balance');
            msg.sender.transfer(_amountETH);
            emit BonusRemoved(msg.sender, _amountETH);
        }
        
        if (_amountToken > 0) {
            require(_checkForSufficientStakingBonusesForToken(_amountToken), 'cannot withdraw above current token bonus balance');
            require(token.transfer(msg.sender, _amountToken), "error: token transfer failed");
            emit BonusRemoved(msg.sender, _amountToken);
        }
        
        return true;
    }
    
    function addLiquidity(uint _term, uint _multiplier, uint _id) external uTokenVet(_id) payable {

        
        require(!getUserMigration(msg.sender), "must not be migrated already");
        require(now >= _users[msg.sender].release, "cannot override current term");
        
        (bool isValid, uint period) = _isValidTerm(_term);
        require(isValid, "must select a valid term");
        require(msg.value > 0, "must send ETH along with transaction");
        if (cap != 0) require(msg.value <= cap, "cannot provide more than the cap");
        
        uint rate = _proportion(msg.value, address(weth), address(token));
        require(token.transferFrom(msg.sender, address(this), rate), "must approve smart contract");
        
        (uint ETH_bonus, uint token_bonus) = getUserBonusPending(msg.sender);
        require(ETH_bonus == 0 && token_bonus == 0, "must first withdraw available bonus");
        
        uint oneTenthOfRate = (rate.mul(10)).div(100);
        token.approve(address(uniswapRouter), rate);

        (uint amountToken, uint amountETH, uint liquidity) = 
        uniswapRouter.addLiquidityETH{value: msg.value}(
            address(token), 
            rate.add(oneTenthOfRate), 
            0, 
            0, 
            address(this), 
            now.add(_012_HOURS_IN_SECONDS));
        
        uint term = _term;
        uint mul = _multiplier;
        uint __id = _id;
        
        _users[msg.sender].start = now;
        _users[msg.sender].release = now.add(term);
        
        totalETHProvided = totalETHProvided.add(amountETH);
        totalTokenProvided = totalTokenProvided.add(amountToken);
        totalProviders++;
        
        uint currentPeriod = _users[msg.sender].period;
        if (currentPeriod != period) {
            _providers[currentPeriod]--;
            _providers[period]++;
            _users[msg.sender].period = period;
        }
        
        uint previousLiquidity = _users[msg.sender].liquidity; 
        _users[msg.sender].liquidity = previousLiquidity.add(liquidity);  
        
        uint wethRP = _calculateReturnPercentage(weth, term);
        uint tokenRP = _calculateReturnPercentage(token, term);
               
        (uint provided_ETH, uint provided_token) = getUserLiquidity(msg.sender);
        
        if (mul == 1) 
        _withMultiplier(term, provided_ETH, provided_token, wethRP, tokenRP, __id);
        else _withoutMultiplier(provided_ETH, provided_token, wethRP, tokenRP);
        
        _updateLastProvision(now, term, provided_token, provided_ETH, mul);
        
        emit LiquidityAdded(msg.sender, liquidity, amountETH, amountToken);
    }
    
    function _withMultiplier(
        uint _term, uint amountETH, uint amountToken, uint wethRP, uint tokenRP, uint _id
    ) internal {

        
        if(_id == 1) 
        _resolveMultiplier(_term, amountETH, amountToken, wethRP, tokenRP, multiplier1);
        else _resolveMultiplier(_term, amountETH, amountToken, wethRP, tokenRP, multiplier2);
    }
    
    function _withoutMultiplier(
        uint amountETH, uint amountToken, uint wethRP, uint tokenRP
    ) internal {

            
        uint addedBonusWeth;
        uint addedBonusToken;
        
        if (_offersBonus(weth) && _offersBonus(token)) {
            
            addedBonusWeth = _calculateBonus(amountETH, wethRP);
            addedBonusToken = _calculateBonus(amountToken, tokenRP);
                
            require(_checkForSufficientStakingBonusesForETH(addedBonusWeth)
            && _checkForSufficientStakingBonusesForToken(addedBonusToken),
            "must be sufficient staking bonuses available in pool");
            
            _users[msg.sender].wethBonus = _users[msg.sender].wethBonus.add(addedBonusWeth);
            _users[msg.sender].tokenBonus = _users[msg.sender].tokenBonus.add(addedBonusToken);
            _users[msg.sender].lastPercentWeth = wethRP;
            _users[msg.sender].lastPercentToken = tokenRP;
            _pendingBonusesWeth = _pendingBonusesWeth.add(addedBonusWeth);
            _pendingBonusesToken = _pendingBonusesToken.add(addedBonusToken);
                
        } else if (_offersBonus(weth) && !_offersBonus(token)) {
                
            addedBonusWeth = _calculateBonus(amountETH, wethRP);
                
            require(_checkForSufficientStakingBonusesForETH(addedBonusWeth), 
            "must be sufficient staking bonuses available in pool");
                
            _users[msg.sender].wethBonus = _users[msg.sender].wethBonus.add(addedBonusWeth);
            _users[msg.sender].lastPercentWeth = wethRP;
            _pendingBonusesWeth = _pendingBonusesWeth.add(addedBonusWeth);
                
        } else if (!_offersBonus(weth) && _offersBonus(token)) {
                
            addedBonusToken = _calculateBonus(amountToken, tokenRP);
                
            require(_checkForSufficientStakingBonusesForToken(addedBonusToken),
            "must be sufficient staking bonuses available in pool");
                
            _users[msg.sender].tokenBonus = _users[msg.sender].tokenBonus.add(addedBonusToken);
            _users[msg.sender].lastPercentToken = tokenRP;
            _pendingBonusesToken = _pendingBonusesToken.add(addedBonusToken);
        }
    }
    
    function _resolveMultiplier(
        uint _term, uint amountETH, uint amountToken, uint wethRP, uint tokenRP, Multiplier _multiplier
    ) internal {

        
        uint addedBonusWeth;
        uint addedBonusToken;
        
        require(_multiplier.balance(msg.sender) > 0, "No Multiplier balance to use");
        if (_term > _multiplier.lockupPeriod(msg.sender)) _multiplier.updateLockupPeriod(msg.sender, _term);
            
        uint multipliedETH = _proportion(_multiplier.balance(msg.sender), uToken1, address(weth));
        uint multipliedToken = _proportion(multipliedETH, address(weth), address(token));
            
        if (_offersBonus(weth) && _offersBonus(token)) {
                        
            if (multipliedETH > amountETH) {
                multipliedETH = (_calculateBonus((amountETH.mul(_multiplier.getMultiplierCeiling())), wethRP));
                addedBonusWeth = multipliedETH;
            } else {
                addedBonusWeth = (_calculateBonus((amountETH.add(multipliedETH)), wethRP));
            }
                
            if (multipliedToken > amountToken) {
                multipliedToken = (_calculateBonus((amountToken.mul(_multiplier.getMultiplierCeiling())), tokenRP));
                addedBonusToken = multipliedToken;
            } else {
                addedBonusToken = (_calculateBonus((amountToken.add(multipliedToken)), tokenRP));
            }
                    
            require(_checkForSufficientStakingBonusesForETH(addedBonusWeth)
            && _checkForSufficientStakingBonusesForToken(addedBonusToken),
            "must be sufficient staking bonuses available in pool");
                                
            _users[msg.sender].wethBonus = _users[msg.sender].wethBonus.add(addedBonusWeth);
            _users[msg.sender].tokenBonus = _users[msg.sender].tokenBonus.add(addedBonusToken);
            _users[msg.sender].lastPercentWeth = wethRP.mul(2);
            _users[msg.sender].lastPercentToken = tokenRP.mul(2);
            _pendingBonusesWeth = _pendingBonusesWeth.add(addedBonusWeth);
            _pendingBonusesToken = _pendingBonusesToken.add(addedBonusToken);
                    
        } else if (_offersBonus(weth) && !_offersBonus(token)) {
                    
            if (multipliedETH > amountETH) {
                multipliedETH = (_calculateBonus((amountETH.mul(_multiplier.getMultiplierCeiling())), wethRP));
                addedBonusWeth = multipliedETH;
            } else {
                addedBonusWeth = (_calculateBonus((amountETH.add(multipliedETH)), wethRP));
            }
                        
            require(_checkForSufficientStakingBonusesForETH(addedBonusWeth), 
            "must be sufficient staking bonuses available in pool");
                    
            _users[msg.sender].wethBonus = _users[msg.sender].wethBonus.add(addedBonusWeth);
            _users[msg.sender].lastPercentWeth = wethRP.mul(2);
            _pendingBonusesWeth = _pendingBonusesWeth.add(addedBonusWeth);
                        
        } else if (!_offersBonus(weth) && _offersBonus(token)) {
            
            if (multipliedToken > amountToken) {
                multipliedToken = (_calculateBonus((amountToken.mul(_multiplier.getMultiplierCeiling())), tokenRP));
                addedBonusToken = multipliedToken;
            } else {
                addedBonusToken = (_calculateBonus((amountToken.add(multipliedToken)), tokenRP));
            }
            
            require(_checkForSufficientStakingBonusesForToken(addedBonusToken),
            "must be sufficient staking bonuses available in pool");
         
            _users[msg.sender].tokenBonus = _users[msg.sender].tokenBonus.add(addedBonusToken);
            _users[msg.sender].lastPercentToken = tokenRP.mul(2);
            _pendingBonusesToken = _pendingBonusesToken.add(addedBonusToken);
        }
    }    
    
    function _updateLastProvision(
        uint timestamp, uint term, uint tokenProvided, 
        uint ethProvided, uint _multiplier
    ) internal {

        
        _users[msg.sender].lastAction = timestamp;
        _users[msg.sender].lastTerm = term;
        _users[msg.sender].lastTokenProvided = tokenProvided;
        _users[msg.sender].lastWethProvided = ethProvided;
        _users[msg.sender].multiplier = _multiplier == 1 ? true : false;
    }
    
    function relockLiquidity(uint _term, uint _multiplier, uint _id) external uTokenVet(_id) returns(bool) {

        
        require(!getUserMigration(msg.sender), "must not be migrated already");
        require(_users[msg.sender].liquidity > 0, "do not have any liquidity to lock");
        require(now >= _users[msg.sender].release, "cannot override current term");
        (bool isValid, uint period) = _isValidTerm(_term);
        require(isValid, "must select a valid term");
        
        (uint ETH_bonus, uint token_bonus) = getUserBonusPending(msg.sender);
        require (ETH_bonus == 0 && token_bonus == 0, 'must withdraw available bonuses first');
        
        (uint provided_ETH, uint provided_token) = getUserLiquidity(msg.sender);
        if (cap != 0) require(provided_ETH <= cap, "cannot provide more than the cap");
        
        uint wethRP = _calculateReturnPercentage(weth, _term);
        uint tokenRP = _calculateReturnPercentage(token, _term);
        
        totalProviders++;
        
        uint currentPeriod = _users[msg.sender].period;
        if (currentPeriod != period) {
            _providers[currentPeriod]--;
            _providers[period]++;
            _users[msg.sender].period = period;
        }
        
        _users[msg.sender].start = now;
        _users[msg.sender].release = now.add(_term);
        
        uint __id = _id;
        uint term = _term;
        uint mul = _multiplier;
        
        if (mul == 1) 
        _withMultiplier(term, provided_ETH, provided_token, wethRP, tokenRP, __id);
        else _withoutMultiplier(provided_ETH, provided_token, wethRP, tokenRP); 
        
        _updateLastProvision(now, term, provided_token, provided_ETH, mul);
        
        return true;
    }
    
    function withdrawLiquidity(uint _lpAmount) external returns(bool) {

        
        require(!getUserMigration(msg.sender), "must not be migrated already");
        
        uint liquidity = _users[msg.sender].liquidity;
        require(_lpAmount > 0 && _lpAmount <= liquidity, "do not have any liquidity");
        require(now >= _users[msg.sender].release, "cannot override current term");
        
        _users[msg.sender].liquidity = liquidity.sub(_lpAmount); 
        
        lpToken.approve(address(uniswapRouter), _lpAmount);                                         
        
        (uint amountToken, uint amountETH) = 
            uniswapRouter.removeLiquidityETH(
                address(token),
                _lpAmount,
                1,
                1,
                msg.sender,
                now);
        
        uint period = _users[msg.sender].period;
        if (_users[msg.sender].liquidity == 0) {
            _users[msg.sender].period = 0;
            _providers[period]--;
            
            _updateLastProvision(0, 0, 0, 0, 0);
            _users[msg.sender].lastPercentWeth = 0;
            _users[msg.sender].lastPercentToken = 0;
        }
        
        emit LiquidityWithdrawn(msg.sender, _lpAmount, amountETH, amountToken);
        return true;
    }
    
    function withdrawUserLP() external returns(bool) {

        
        require(!getUserMigration(msg.sender), "must not be migrated already");
        
        uint liquidity = _users[msg.sender].liquidity;
        require(liquidity > 0, "do not have any liquidity");
        require(now >= _users[msg.sender].release, "cannot override current term");
        
        uint period = _users[msg.sender].period;
        _users[msg.sender].liquidity = 0; 
        _users[msg.sender].period = 0;
        _providers[period]--;
        
        _updateLastProvision(0, 0, 0, 0, 0);
        _users[msg.sender].lastPercentWeth = 0;
        _users[msg.sender].lastPercentToken = 0;
        
        lpToken.transfer(msg.sender, liquidity);                                         
        
        emit LPWithdrawn(msg.sender, liquidity);
        return true;
    }
    
    function endStake(uint _id) external uTokenVet(_id) returns(bool) {

        
        require(_users[msg.sender].release > now, "no current lockup");
        
        _withdrawUserBonus(_id);
        
        (uint ethBonus, uint tokenBonus) = getUserBonusPending(msg.sender);
        _zeroBalances();
        
        if (ethBonus > 0 && tokenBonus > 0) {
            
            _pendingBonusesWeth = _pendingBonusesWeth.sub(ethBonus);
            _pendingBonusesToken = _pendingBonusesToken.sub(tokenBonus);
            
        } else if (ethBonus > 0 && tokenBonus == 0) 
            _pendingBonusesWeth = _pendingBonusesWeth.sub(ethBonus);
        
        else if (ethBonus == 0 && tokenBonus > 0)
            _pendingBonusesToken = _pendingBonusesToken.sub(tokenBonus);
        
        emit StakeEnded(msg.sender, ethBonus, tokenBonus);
        return true;
    }
    
    function withdrawUserBonus(uint _id) external uTokenVet(_id) returns(bool) {

        
        (uint ETH_bonus, uint token_bonus) = getUserBonusAvailable(msg.sender);
        require(ETH_bonus > 0 || token_bonus > 0, "you do not have any bonus available");
        
        _withdrawUserBonus(_id);
        
        if (_users[msg.sender].release <= now) {
            _zeroBalances();
        }
        return true;
    }
    
    function _zeroBalances() internal {

        
        _users[msg.sender].wethWithdrawn = 0;
        _users[msg.sender].tokenWithdrawn = 0;
        _users[msg.sender].wethBonus = 0;
        _users[msg.sender].tokenBonus = 0;
    }
    
    function _withdrawUserBonus(uint _id) internal {

        
        uint releasedToken = _calculateTokenReleasedAmount(msg.sender);
        uint releasedETH = _calculateETHReleasedAmount(msg.sender);
        
        if (releasedToken > 0 && releasedETH > 0) {
            
            _withdrawUserTokenBonus(msg.sender, releasedToken, _id);
            _withdrawUserETHBonus(msg.sender, releasedETH, _id);
            
        } else if (releasedETH > 0 && releasedToken == 0) 
            _withdrawUserETHBonus(msg.sender, releasedETH, _id);
        
        else if (releasedETH == 0 && releasedToken > 0)
            _withdrawUserTokenBonus(msg.sender, releasedToken, _id);
    }
    
    function _withdrawUserETHBonus(address payable _user, uint releasedAmount, uint _id) internal returns(bool) {

     
        _users[_user].wethWithdrawn = _users[_user].wethWithdrawn.add(releasedAmount);
        _pendingBonusesWeth = _pendingBonusesWeth.sub(releasedAmount);
        
        (uint fee, uint feeInETH) = _calculateETHFee(releasedAmount);
        
        if(_id == 1) require(IERC20(uToken1).transferFrom(_user, platformWallet, fee), "must approve fee");
        else require(IERC20(uToken2).transferFrom(_user, platformWallet, fee), "must approve fee");
        
        _user.transfer(releasedAmount);
        
        emit UserETHBonusWithdrawn(_user, releasedAmount, feeInETH);
        return true;
    }
    
    function _withdrawUserTokenBonus(address _user, uint releasedAmount, uint _id) internal returns(bool) {

        
        _users[_user].tokenWithdrawn = _users[_user].tokenWithdrawn.add(releasedAmount);
        _pendingBonusesToken = _pendingBonusesToken.sub(releasedAmount);
        
        (uint fee, uint feeInToken) = _calculateTokenFee(releasedAmount);
        if(_id == 1) require(IERC20(uToken1).transferFrom(_user, platformWallet, fee), "must approve fee");
        else require(IERC20(uToken2).transferFrom(_user, platformWallet, fee), "must approve fee");
        
        token.transfer(_user, releasedAmount);
    
        emit UserTokenBonusWithdrawn(_user, releasedAmount, feeInToken);
        return true;
    }
    
    function _proportion(uint _amount, address _tokenA, address _tokenB) internal view returns(uint tokenBAmount) {

        
        (uint reserveA, uint reserveB) = UniswapV2Library.getReserves(address(iUniswapV2Factory), _tokenA, _tokenB);
        
        return UniswapV2Library.quote(_amount, reserveA, reserveB);
    }
    
    function _calculateTokenReleasedAmount(address _user) internal view returns(uint) {


        uint release = _users[_user].release;
        uint start = _users[_user].start;
        uint taken = _users[_user].tokenWithdrawn;
        uint tokenBonus = _users[_user].tokenBonus;
        uint releasedPct;
        
        if (now >= release) releasedPct = 100;
        else releasedPct = ((now.sub(start)).mul(100000)).div((release.sub(start)).mul(1000));
        
        uint released = (((tokenBonus).mul(releasedPct)).div(100));
        return released.sub(taken);
    }
    
    function _calculateETHReleasedAmount(address _user) internal view returns(uint) {

        
        uint release = _users[_user].release;
        uint start = _users[_user].start;
        uint taken = _users[_user].wethWithdrawn;
        uint wethBonus = _users[_user].wethBonus;
        uint releasedPct;
        
        if (now >= release) releasedPct = 100;
        else releasedPct = ((now.sub(start)).mul(10000)).div((release.sub(start)).mul(100));
        
        uint released = (((wethBonus).mul(releasedPct)).div(100));
        return released.sub(taken);
    }
    
    function _calculateTokenFee(uint _amount) internal view returns(uint uTokenFee, uint tokenFee) {

        
        uint fee = (_amount.mul(10)).div(100);
        uint feeInETH = _proportion(fee, address(token), address(weth));
        uint feeInUtoken = _proportion(feeInETH, address(weth), uToken1); 
        
        return (feeInUtoken, fee);
    }
    
    function _calculateETHFee(uint _amount) internal view returns(uint uTokenFee, uint ethFee) {

        
        uint fee = (_amount.mul(10)).div(100);
        uint feeInUtoken = _proportion(fee, address(weth), uToken1); 
        
        return (feeInUtoken, fee);
    }
    
    function calculateETHBonusFee(address _user) external view returns(uint ETH_Fee) {

        
        uint wethReleased = _calculateETHReleasedAmount(_user);
        
        if (wethReleased > 0) {
            
            (uint feeForWethInUtoken,) = _calculateETHFee(wethReleased);
            
            return feeForWethInUtoken;
            
        } else return 0;
    }
    
    function calculateTokenBonusFee(address _user) external view returns(uint token_Fee) {

        
        uint tokenReleased = _calculateTokenReleasedAmount(_user);
        
        if (tokenReleased > 0) {
            
            (uint feeForTokenInUtoken,) = _calculateTokenFee(tokenReleased);
            
            return feeForTokenInUtoken;
            
        } else return 0;
    }
    
    function _calculateBonus(uint _amount, uint _returnPercentage) internal pure returns(uint) {

        
        return ((_amount.mul(_returnPercentage)).div(100000)) / 2;                                  //  1% = 1000
    }
    
    function _calculateReturnPercentage(IERC20 _token, uint _term) internal view returns(uint) {

        
        if (_token == weth) {
            if (_term == period1) return period1RPWeth;
            else if (_term == period2) return period2RPWeth;
            else if (_term == period3) return period3RPWeth;
            else if (_term == period4) return period4RPWeth;
            else return 0;
            
        } else if (_token == token) {
            if (_term == period1) return period1RPToken;
            else if (_term == period2) return period2RPToken;
            else if (_term == period3) return period3RPToken;
            else if (_term == period4) return period4RPToken;
            else return 0;
        }
    }
    
    function _isValidTerm(uint _term) internal view returns(bool isValid, uint Period) {

        
        if (_term == period1) return (true, 1);
        else if (_term == period2) return (true, 2);
        else if (_term == period3) return (true, 3);
        else if (_term == period4) return (true, 4);
        else return (false, 0);
    }
    
    function getUserLiquidity(address _user) public view returns(uint provided_ETH, uint provided_token) {

        
        uint total = lpToken.totalSupply();
        uint ratio = ((_users[_user].liquidity).mul(scalar)).div(total);
        uint tokenHeld = token.balanceOf(address(lpToken));
        uint wethHeld = weth.balanceOf(address(lpToken));
        
        return ((ratio.mul(wethHeld)).div(scalar), (ratio.mul(tokenHeld)).div(scalar));
    }
    
    function getUserMigration(address _user) public view returns (bool) {

        
        return _users[_user].migrated;
    }
    
    function _offersBonus(IERC20 _token) internal view returns (bool) {

        
        if (_token == weth) {
            uint wethRPTotal = period1RPWeth.add(period2RPWeth).add(period3RPWeth).add(period4RPWeth);
            if (wethRPTotal > 0) return true; 
            else return false;
            
        } else if (_token == token) {
            uint tokenRPTotal = period1RPToken.add(period2RPToken).add(period3RPToken).add(period4RPToken);
            if (tokenRPTotal > 0) return true;
            else return false;
        }
    }
    
    function _checkForSufficientStakingBonusesForETH(uint _amount) internal view returns(bool) {

        
        if ((address(this).balance).sub(_pendingBonusesWeth) >= _amount) {
            return true;
        } else {
            return false;
        }
    }
    
    function _checkForSufficientStakingBonusesForToken(uint _amount) internal view returns(bool) {

       
        if ((token.balanceOf(address(this)).sub(_pendingBonusesToken)) >= _amount) {
            
            return true;
            
        } else {
            
            return false;
        }
    }
    
    function getUserRelease(address _user) external view returns(uint release_time) {

        
        uint release = _users[_user].release;
        if (release > now) {
            
            return (release.sub(now));
       
        } else {
            
            return 0;
        }
        
    }
    
    function getUserBonusPending(address _user) public view returns(uint ETH_bonus, uint token_bonus) {

        
        uint takenWeth = _users[_user].wethWithdrawn;
        uint takenToken = _users[_user].tokenWithdrawn;
        
        return (_users[_user].wethBonus.sub(takenWeth), _users[_user].tokenBonus.sub(takenToken));
    }
    
    function getUserBonusAvailable(address _user) public view returns(uint ETH_Released, uint token_Released) {

        
        uint ETHValue = _calculateETHReleasedAmount(_user);
        uint tokenValue = _calculateTokenReleasedAmount(_user);
        
        return (ETHValue, tokenValue);
    }   
    
    function getUserLPTokens(address _user) external view returns(uint user_LP) {


        return _users[_user].liquidity;
    }
    
    function getLPAddress() external view returns(address) {

        
        return address(lpToken);
    }
    
    function getTotalLPTokens() external view returns(uint) {

        
        return lpToken.balanceOf(address(this));
    }
    
    function getAvailableBonus() external view returns(uint available_ETH, uint available_token) {

        
        available_ETH = (address(this).balance).sub(_pendingBonusesWeth);
        available_token = (token.balanceOf(address(this))).sub(_pendingBonusesToken);
        
        return (available_ETH, available_token);
    }
    
    function getCap() external view returns(uint maxETH) {

        
        return cap;
    }
    
    function getTermPeriodAndReturnPercentages() external view returns(
        uint Term_Period_1, uint Term_Period_2, uint Term_Period_3, uint Term_Period_4,
        uint Period_1_Return_Percentage_Token, uint Period_2_Return_Percentage_Token,
        uint Period_3_Return_Percentage_Token, uint Period_4_Return_Percentage_Token,
        uint Period_1_Return_Percentage_ETH, uint Period_2_Return_Percentage_ETH,
        uint Period_3_Return_Percentage_ETH, uint Period_4_Return_Percentage_ETH
    ) {

        
        return (
            period1, period2, period3, period4, period1RPToken, period2RPToken, period3RPToken, 
            period4RPToken,period1RPWeth, period2RPWeth, period3RPWeth, period4RPWeth);
    }
    
    function analytics() external view returns(uint Total_ETH_Provided, 
        uint Total_Tokens_Provided, uint Total_Providers,
        uint Current_Term_1, uint Current_Term_2, 
        uint Current_Term_3, uint Current_Term_4
    ) {

        
        return(
            totalETHProvided, totalTokenProvided, totalProviders, 
            _providers[1], _providers[2], _providers[3], _providers[4]);
    }
    
    function multiplierContract() external view returns(address Token1, address Token2) {

        
        return (address(multiplier1), address(multiplier2));
    }
    
    function feeToken() external view returns(address _uToken1, address _uToken2) {

        
        return (uToken1, uToken2);
    }
    
    function feeReceiver() external view returns(address) {

        
        return platformWallet;
    }
    
    function lastProvision(address _user) external view returns(
        uint timestamp, uint term, uint token_provided, 
        uint eth_provided, bool multiplier, 
        uint percentageGottenToken, uint percentageGottenWeth
    ) {

        
        timestamp = _users[_user].lastAction;
        term = _users[_user].lastTerm;
        token_provided = _users[_user].lastTokenProvided;
        eth_provided = _users[_user].lastWethProvided;
        multiplier = _users[_user].multiplier;
        percentageGottenToken = _users[_user].lastPercentToken;
        percentageGottenWeth = _users[_user].lastPercentWeth;
        
        return(
            timestamp, term, token_provided, eth_provided,
            multiplier, percentageGottenToken, percentageGottenWeth
        );
    }
    
}