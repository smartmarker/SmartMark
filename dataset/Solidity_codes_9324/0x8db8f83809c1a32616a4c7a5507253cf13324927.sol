pragma solidity >=0.8.0;

interface IERC20 {

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);

    function name() external view returns (string memory);


    function symbol() external view returns (string memory);


    function decimals() external view returns (uint8);


    function totalSupply() external view returns (uint256);


    function balanceOf(address owner) external view returns (uint256);


    function allowance(address owner, address spender) external view returns (uint256);


    function approve(address spender, uint256 value) external returns (bool);


    function transfer(address to, uint256 value) external returns (bool);


    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);

}pragma solidity >=0.6.0 <=0.8.0;

library SafeMath {

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        require(c >= a, 'SafeMath: addition overflow');

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, 'SafeMath: subtraction overflow');
    }

    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {

        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, 'SafeMath: multiplication overflow');

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, 'SafeMath: division by zero');
    }

    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {

        require(b > 0, errorMessage);
        uint256 c = a / b;

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return mod(a, b, 'SafeMath: modulo by zero');
    }

    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {

        require(b != 0, errorMessage);
        return a % b;
    }
}pragma solidity >=0.8.0;


contract ERC20 is IERC20 {

    using SafeMath for uint256;

    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 internal _totalSupply;

    string public override name;
    string public override symbol;
    uint8 public override decimals;

    function initialize(
        string memory _name,
        string memory _symbol,
        uint8 _decimal
    ) internal {

        name = _name;
        symbol = _symbol;
        decimals = _decimal;
    }

    function totalSupply() public view override returns (uint256) {

        return _totalSupply;
    }

    function balanceOf(address account) public view override returns (uint256) {

        return _balances[account];
    }

    function transfer(address recipient, uint256 amount)
        public
        virtual
        override
        returns (bool)
    {

        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender)
        public
        view
        virtual
        override
        returns (uint256)
    {

        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount)
        public
        virtual
        override
        returns (bool)
    {

        _approve(_msgSender(), spender, amount);
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
            _msgSender(),
            _allowances[sender][_msgSender()].sub(
                amount,
                "ERC20: transfer amount exceeds allowance"
            )
        );
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue)
        public
        virtual
        returns (bool)
    {

        _approve(
            _msgSender(),
            spender,
            _allowances[_msgSender()][spender].add(addedValue)
        );
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue)
        public
        virtual
        returns (bool)
    {

        _approve(
            _msgSender(),
            spender,
            _allowances[_msgSender()][spender].sub(
                subtractedValue,
                "ERC20: decreased allowance below zero"
            )
        );
        return true;
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {

        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(
            amount,
            "ERC20: transfer amount exceeds balance"
        );
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(
            amount,
            "ERC20: burn amount exceeds balance"
        );
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual {}


    function _msgSender() private view returns (address) {

        return msg.sender;
    }
}pragma solidity >=0.8.0;

library TransferHelper {

    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {

        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper: APPROVE_FAILED'
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {

        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper: TRANSFER_FAILED'
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {

        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper: TRANSFER_FROM_FAILED'
        );
    }

    function safeTransferETH(address to, uint256 value) internal {

        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper: ETH_TRANSFER_FAILED');
    }
}pragma solidity >=0.8.0;

interface IConfig {

    enum EventType {FUND_CREATED, FUND_UPDATED, STAKE_CREATED, STAKE_UPDATED, REG_CREATED, REG_UPDATED, PFUND_CREATED, PFUND_UPDATED}

    function ceo() external view returns (address);


    function protocolPool() external view returns (address);


    function protocolToken() external view returns (address);


    function feeTo() external view returns (address);


    function nameRegistry() external view returns (address);



    function tokenMinFundSize(address token) external view returns (uint256);


    function investFeeRate() external view returns (uint256);


    function redeemFeeRate() external view returns (uint256);


    function claimFeeRate() external view returns (uint256);


    function poolCreationRate() external view returns (uint256);


    function slot0() external view returns (uint256);


    function slot1() external view returns (uint256);


    function slot2() external view returns (uint256);


    function slot3() external view returns (uint256);


    function slot4() external view returns (uint256);


    function notify(EventType _type, address _src) external;

}pragma solidity >=0.8.0;


interface IFundManager {

    function feeTo() external view returns (address);


    function broadcast() external;


    function uniswapV2Router() external view returns (address);


    function getConfig() external view returns (IConfig);

}pragma solidity >=0.8.0;

interface IFund {

    enum Status {Raise, Run, Liquidation, RaiseFailure}

    function invest(address owner, uint256 amount) external;


    function initialize(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        uint128 _minSize,
        uint256[2] memory _dates,
        uint16[4] memory _rates,
        address _manager,
        uint256 _amountOfManager,
        address[] memory _tokens
    ) external;


    function tokens() external view returns (address[] memory);


    function getToken(uint256) external view returns (address);

}pragma solidity >=0.6.2;

interface IUniswapV2Router02 {

    function factory() external pure returns (address);


    function WETH() external pure returns (address);


    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    )
        external
        returns (
            uint256 amountA,
            uint256 amountB,
            uint256 liquidity
        );


    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    )
        external
        payable
        returns (
            uint256 amountToken,
            uint256 amountETH,
            uint256 liquidity
        );


    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB);


    function removeLiquidityETH(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountToken, uint256 amountETH);


    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline,
        bool approveMax,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 amountA, uint256 amountB);


    function removeLiquidityETHWithPermit(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline,
        bool approveMax,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 amountToken, uint256 amountETH);


    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);


    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);


    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);


    function swapTokensForExactETH(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);


    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);


    function swapETHForExactTokens(
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);


    function quote(
        uint256 amountA,
        uint256 reserveA,
        uint256 reserveB
    ) external pure returns (uint256 amountB);


    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) external pure returns (uint256 amountOut);


    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) external pure returns (uint256 amountIn);


    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);


    function getAmountsIn(uint256 amountOut, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);


    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountETH);


    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline,
        bool approveMax,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 amountETH);


    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;


    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable;


    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;

}pragma solidity ^0.8.0;





interface IUniswapV2Factory {

    function getPair(address token0, address token1) external view returns (address);


    function feeTo() external view returns (address);

}

interface IUniswapV2Pair {

    function getReserves() external view returns (uint256, uint256);

}

contract Fund is IFund, ERC20 {

    event StatuChanged(uint256 status);
    event Invested(address indexed investor, uint256 amount);
    event Liquidated(address indexed liquidator, uint256 netValue);
    event Redeemed(address indexed redeemer, uint256 dfAmount);

    uint256 public constant UintMax = 2**256 - 1;

    uint128 public minSize; // raise size

    uint128 public finalNetValue;

    uint32 public startDate;

    uint32 public endDate;

    uint16 public hurdleRate;

    uint16 public estimatedROE;

    uint16 public performanceFee;

    uint16 public maxDrawdown;

    Status private fundStatus;

    bool locker;

    bool initialized;

    address public manager;

    address public controller; // FundManager address

    address[] public override getToken; // tradeable getToken

    uint256 public reservePoolDF; // amount of raise token of manager to create Pool

    modifier lock() {

        require(!locker, "reentrant call");
        locker = true;
        _;
        locker = false;
    }

    modifier onlyManager() {

        require(msg.sender == manager, "only manager");
        _;
    }

    modifier onlyController() {

        require(msg.sender == controller, "only controller");
        _;
    }

    modifier nonContract() {

        uint256 size;
        address account = msg.sender;
        assembly {
            size := extcodesize(account)
        }
        require(size == 0, "CONTRACT_INVOKE");
        _;
    }

    modifier ready() {

        require(initialized, "not initialized");
        _;
    }

    modifier inRaise() {

        require(fundStatus == Status.Raise && startDate >= block.timestamp, "status != raise");
        _;
    }

    modifier inRun() {

        require(fundStatus == Status.Run, "status != run");
        _;
    }

    constructor() {}

    function initialize(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        uint128 _minSize,
        uint256[2] memory _dates,
        uint16[4] memory _rates,
        address _manager,
        uint256 _amountOfManager,
        address[] memory _tokens
    ) external override lock() {

        require(!initialized, "alreday initialized");
        super.initialize(_name, _symbol, _decimals);
        initialized = true;
        controller = msg.sender;
        require(_tokens.length > 1, "token length = 1");
        IERC20 base = IERC20(_tokens[0]);
        require(base.balanceOf(address(this)) == _amountOfManager, "contract's balance != amount");
        getToken = _tokens;

        require(
            _dates[1] > _dates[0] && _dates[1] <= (_dates[0] + 1000 days),
            "endDate < startDate or endDate - startDate > 1000 days"
        );
        require(_dates[0] > block.timestamp, "start date < current time");
        startDate = uint32(_dates[0]);
        endDate = uint32(_dates[1]);

        minSize = _minSize;

        require(_amountOfManager >= minSize / 50, "amountOfManager < minSize * 2%");

        hurdleRate = _rates[0];
        require(hurdleRate >= 110, "hurdleRate < 110");
        performanceFee = _rates[1];
        require(performanceFee <= 80, "performanceFee > 80");
        maxDrawdown = _rates[2];
        require(maxDrawdown < 100 && maxDrawdown > 5, "maxDrawdown => 100 or maxDrawdown <= 5");
        estimatedROE = _rates[3];

        manager = _manager;
        IConfig config = IFundManager(controller).getConfig();
        require(config.poolCreationRate() > 0, "poolCreationRate==0");
        reservePoolDF = (_amountOfManager * config.poolCreationRate()) / 10000;
        _mint(manager, _amountOfManager - reservePoolDF);
        _mint(address(this), reservePoolDF);
    }

    function invest(address _owner, uint256 _amount) external override ready() lock() inRaise() onlyController() {

        _mint(_owner, _amount);

        if (_totalSupply >= minSize) {
            minSize = uint128(_totalSupply);
            fundStatus = Status.Run;
            _createPool();
        }
        _notify();
    }

    function redeem() external ready() lock() {

        address redeemer = msg.sender;
        if (fundStatus == Status.Raise || fundStatus == Status.Run) {
            _liquidate(redeemer);
        }

        uint256 dfBalance = balanceOf(redeemer);
        for (uint256 i = 0; i < getToken.length; i++) {
            address token = getToken[i];
            uint256 total = IERC20(token).balanceOf(address(this));
            if (total > 0) {
                _redeemToken(token, redeemer, (total * dfBalance) / _totalSupply);
            }
        }
        _burn(redeemer, dfBalance);
        _notify();
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        uint256 deadline
    ) external inRun() ready() nonContract() onlyManager() {

        require(deadline >= block.timestamp, "expired");
        require(path.length > 1, "path length <= 1");
        address last = path[path.length - 1];
        require(_inGetToken(last), "not in getToken");
        address first = path[0];
        address uniswapV2Router = IFundManager(controller).uniswapV2Router();
        _checkAndSetMaxAllowanceToUniswap(first, uniswapV2Router);
        IUniswapV2Router02(uniswapV2Router).swapExactTokensForTokens(
            amountIn,
            amountOutMin,
            path,
            address(this),
            block.timestamp
        );
        _notify();
    }

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        uint256 deadline
    ) external inRun() ready() nonContract() onlyManager() {

        require(deadline >= block.timestamp, "expired");
        require(path.length > 1, "path length <= 1");
        address last = path[path.length - 1];
        require(_inGetToken(last), "not in getToken");
        address first = path[0];
        address uniswapV2Router = IFundManager(controller).uniswapV2Router();
        _checkAndSetMaxAllowanceToUniswap(first, uniswapV2Router);
        IUniswapV2Router02(uniswapV2Router).swapTokensForExactTokens(
            amountOut,
            amountInMax,
            path,
            address(this),
            block.timestamp
        );
        _notify();
    }

    function status() external view returns (Status) {

        if (fundStatus == Status.Raise && _isRaiseFailure()) return Status.RaiseFailure;
        if (fundStatus == Status.Run && block.timestamp >= endDate) return Status.Liquidation;
        return fundStatus;
    }

    function tokens() external view override returns (address[] memory) {

        return getToken;
    }

    function netValue() external view returns (uint256) {

        return _netValue();
    }

    function _inGetToken(address _token) internal view returns (bool) {

        for (uint256 i; i < getToken.length; i++) {
            if (_token == getToken[i]) return true;
        }

        return false;
    }

    function _isRaiseFailure() private view returns (bool) {

        return
            fundStatus == Status.RaiseFailure ||
            (fundStatus == Status.Raise && block.timestamp > startDate && _totalSupply < minSize);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {

        require(fundStatus != Status.Raise || from == address(0), "not allow transfering in raise");
        require(from != manager || to == address(0), "not allow manager transfering");
    }

    function _createPool() private {

        uint256 liquidity = balanceOf(address(this));
        address uniswapV2Router = IFundManager(controller).uniswapV2Router();
        address base = getToken[0];
        TransferHelper.safeApprove(base, uniswapV2Router, UintMax);
        TransferHelper.safeApprove(address(this), uniswapV2Router, UintMax);
        IUniswapV2Router02 router = IUniswapV2Router02(uniswapV2Router);

        router.addLiquidity(address(this), base, liquidity, liquidity, 0, 0, manager, block.timestamp);
    }

    function _notify() private {

        IFundManager(controller).getConfig().notify(IConfig.EventType.FUND_UPDATED, address(this));
    }

    function _netValue() private view returns (uint256) {

        if (fundStatus == Status.Raise || fundStatus == Status.RaiseFailure) {
            return _totalSupply;
        }

        if (fundStatus == Status.Liquidation) {
            return finalNetValue;
        }
        address baseAsset = getToken[0];
        uint256 amount = IERC20(baseAsset).balanceOf(address(this));
        IUniswapV2Router02 router = IUniswapV2Router02(IFundManager(controller).uniswapV2Router());
        for (uint256 i = 1; i < getToken.length; i++) {
            uint256 balance = IERC20(getToken[i]).balanceOf(address(this));
            if (balance > 0) {
                address token = getToken[i];
                address pair = IUniswapV2Factory(router.factory()).getPair(baseAsset, token);
                if (pair == address(0)) {
                    continue;
                }
                (uint256 baseAssetReserve, uint256 tokenReserve) = _getReserves(pair, baseAsset, token);
                amount += _quote(balance, tokenReserve, baseAssetReserve);
            }
        }

        return amount;
    }

    function _getReserves(
        address _pair,
        address _tokenA,
        address _tokenB
    ) private view returns (uint256 reserveA, uint256 reserveB) {

        address token0 = _tokenA < _tokenB ? _tokenA : _tokenB;
        (uint256 reserve0, uint256 reserve1) = IUniswapV2Pair(_pair).getReserves();
        return token0 == _tokenA ? (reserve0, reserve1) : (reserve1, reserve0);
    }

    function _quote(
        uint256 amountA,
        uint256 reserveA,
        uint256 reserveB
    ) internal pure returns (uint256 amountB) {

        require(amountA > 0, "UniswapV2Library: INSUFFICIENT_AMOUNT");
        require(reserveA > 0 && reserveB > 0, "UniswapV2Library: INSUFFICIENT_LIQUIDITY");
        amountB = (amountA * reserveB) / reserveA;
    }

    function _liquidate(address _liquidator) private {

        require(balanceOf(_liquidator) > 0, "balance == 0, not investor");
        uint256 value = _netValue();
        finalNetValue = uint128(value);
        uint256 maxDrawdownValue = (_totalSupply * maxDrawdown) / 100;
        require(
            block.timestamp > endDate ||
                _isRaiseFailure() ||
                (fundStatus == Status.Run && (_liquidator == manager || value <= maxDrawdownValue)),
            "now <= end date or status != failure or liquidator != manager or netValue >= maxDrawdownValue"
        );

        uint256 total = balanceOf(address(this));
        if (total > 0) {
            fundStatus = Status.RaiseFailure;
            _transfer(address(this), manager, total);
            return;
        }
        fundStatus = Status.Liquidation;
        _distributeHurdleReward();
    }

    function _distributeHurdleReward() private {

        address base = getToken[0];
        uint256 value = IERC20(base).balanceOf(address(this));
        uint256 hurdleLine = (minSize * hurdleRate) / 100;
        if (value > hurdleLine) {
            uint256 reward = ((value - hurdleLine) * performanceFee) / 100;
            _redeemToken(base, manager, reward);
        }
    }

    function _redeemToken(
        address _token,
        address _redeemer,
        uint256 _amountOfRedeemer
    ) private {

        IConfig config = IFundManager(controller).getConfig();
        uint256 out =
            fundStatus == Status.Liquidation
                ? (_amountOfRedeemer * (10000 - config.redeemFeeRate())) / 10000
                : _amountOfRedeemer;

        uint256 fee = _amountOfRedeemer - out;
        if (out > 0) {
            TransferHelper.safeTransfer(_token, _redeemer, out);
        }
        if (fee > 0) {
            TransferHelper.safeTransfer(_token, config.feeTo(), fee);
        }
    }

    function _checkAndSetMaxAllowanceToUniswap(address _token, address _router) private {

        IERC20 token = IERC20(_token);
        uint256 uniAllowance = token.allowance(address(this), _router);
        if (uniAllowance <= UintMax) {
            token.approve(_router, UintMax);
        }
    }
}