


pragma solidity ^0.6.0;

interface IERC20 {

    function totalSupply() external view returns (uint256);


    function balanceOf(address account) external view returns (uint256);


    function transfer(address recipient, uint256 amount) external returns (bool);


    function allowance(address owner, address spender) external view returns (uint256);


    function approve(address spender, uint256 amount) external returns (bool);


    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}


pragma solidity 0.6.6;



interface IERC20Ext is IERC20 {

    function decimals() external view returns (uint8 digits);

}


pragma solidity 0.6.6;



interface IKyberReserve {

    function trade(
        IERC20Ext srcToken,
        uint256 srcAmount,
        IERC20Ext destToken,
        address payable destAddress,
        uint256 conversionRate,
        bool validate
    ) external payable returns (bool);


    function getConversionRate(
        IERC20Ext src,
        IERC20Ext dest,
        uint256 srcQty,
        uint256 blockNumber
    ) external view returns (uint256);

}


pragma solidity 0.6.6;



interface IWeth is IERC20Ext {

    function deposit() external payable;

    function withdraw(uint256 wad) external;

}


pragma solidity 0.6.6;


interface IKyberSanity {

    function getSanityRate(IERC20Ext src, IERC20Ext dest) external view returns (uint256);

}


pragma solidity 0.6.6;



interface IConversionRates {


    function recordImbalance(
        IERC20Ext token,
        int buyAmount,
        uint256 rateUpdateBlock,
        uint256 currentBlock
    ) external;


    function getRate(
        IERC20Ext token,
        uint256 currentBlockNumber,
        bool buy,
        uint256 qty
    ) external view returns(uint256);

}


pragma solidity 0.6.6;



contract Utils {

    IERC20Ext internal constant ETH_TOKEN_ADDRESS = IERC20Ext(
        0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
    );
    IERC20Ext internal constant USDT_TOKEN_ADDRESS = IERC20Ext(
        0xdAC17F958D2ee523a2206206994597C13D831ec7
    );
    IERC20Ext internal constant DAI_TOKEN_ADDRESS = IERC20Ext(
        0x6B175474E89094C44Da98b954EedeAC495271d0F
    );
    IERC20Ext internal constant USDC_TOKEN_ADDRESS = IERC20Ext(
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    );
    IERC20Ext internal constant WBTC_TOKEN_ADDRESS = IERC20Ext(
        0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599
    );
    IERC20Ext internal constant KNC_TOKEN_ADDRESS = IERC20Ext(
        0xdd974D5C2e2928deA5F71b9825b8b646686BD200
    );
    uint256 public constant BPS = 10000; // Basic Price Steps. 1 step = 0.01%
    uint256 internal constant PRECISION = (10**18);
    uint256 internal constant MAX_QTY = (10**28); // 10B tokens
    uint256 internal constant MAX_RATE = (PRECISION * 10**7); // up to 10M tokens per eth
    uint256 internal constant MAX_DECIMALS = 18;
    uint256 internal constant ETH_DECIMALS = 18;
    uint256 internal constant MAX_ALLOWANCE = uint256(-1); // token.approve inifinite

    mapping(IERC20Ext => uint256) internal decimals;

    function getSetDecimals(IERC20Ext token) internal returns (uint256 tokenDecimals) {

        tokenDecimals = getDecimalsConstant(token);
        if (tokenDecimals > 0) return tokenDecimals;

        tokenDecimals = decimals[token];
        if (tokenDecimals == 0) {
            tokenDecimals = token.decimals();
            decimals[token] = tokenDecimals;
        }
    }

    function getBalance(IERC20Ext token, address user) internal view returns (uint256) {

        if (token == ETH_TOKEN_ADDRESS) {
            return user.balance;
        } else {
            return token.balanceOf(user);
        }
    }

    function getDecimals(IERC20Ext token) internal view returns (uint256 tokenDecimals) {

        tokenDecimals = getDecimalsConstant(token);
        if (tokenDecimals > 0) return tokenDecimals;

        tokenDecimals = decimals[token];
        return (tokenDecimals > 0) ? tokenDecimals : token.decimals();
    }

    function calcDestAmount(
        IERC20Ext src,
        IERC20Ext dest,
        uint256 srcAmount,
        uint256 rate
    ) internal view returns (uint256) {

        return calcDstQty(srcAmount, getDecimals(src), getDecimals(dest), rate);
    }

    function calcSrcAmount(
        IERC20Ext src,
        IERC20Ext dest,
        uint256 destAmount,
        uint256 rate
    ) internal view returns (uint256) {

        return calcSrcQty(destAmount, getDecimals(src), getDecimals(dest), rate);
    }

    function calcDstQty(
        uint256 srcQty,
        uint256 srcDecimals,
        uint256 dstDecimals,
        uint256 rate
    ) internal pure returns (uint256) {

        require(srcQty <= MAX_QTY, "srcQty > MAX_QTY");
        require(rate <= MAX_RATE, "rate > MAX_RATE");

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS, "dst - src > MAX_DECIMALS");
            return (srcQty * rate * (10**(dstDecimals - srcDecimals))) / PRECISION;
        } else {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS, "src - dst > MAX_DECIMALS");
            return (srcQty * rate) / (PRECISION * (10**(srcDecimals - dstDecimals)));
        }
    }

    function calcSrcQty(
        uint256 dstQty,
        uint256 srcDecimals,
        uint256 dstDecimals,
        uint256 rate
    ) internal pure returns (uint256) {

        require(dstQty <= MAX_QTY, "dstQty > MAX_QTY");
        require(rate <= MAX_RATE, "rate > MAX_RATE");

        uint256 numerator;
        uint256 denominator;
        if (srcDecimals >= dstDecimals) {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS, "src - dst > MAX_DECIMALS");
            numerator = (PRECISION * dstQty * (10**(srcDecimals - dstDecimals)));
            denominator = rate;
        } else {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS, "dst - src > MAX_DECIMALS");
            numerator = (PRECISION * dstQty);
            denominator = (rate * (10**(dstDecimals - srcDecimals)));
        }
        return (numerator + denominator - 1) / denominator; //avoid rounding down errors
    }

    function calcRateFromQty(
        uint256 srcAmount,
        uint256 destAmount,
        uint256 srcDecimals,
        uint256 dstDecimals
    ) internal pure returns (uint256) {

        require(srcAmount <= MAX_QTY, "srcAmount > MAX_QTY");
        require(destAmount <= MAX_QTY, "destAmount > MAX_QTY");

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS, "dst - src > MAX_DECIMALS");
            return ((destAmount * PRECISION) / ((10**(dstDecimals - srcDecimals)) * srcAmount));
        } else {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS, "src - dst > MAX_DECIMALS");
            return ((destAmount * PRECISION * (10**(srcDecimals - dstDecimals))) / srcAmount);
        }
    }

    function getDecimalsConstant(IERC20Ext token) internal pure returns (uint256) {

        if (token == ETH_TOKEN_ADDRESS) {
            return ETH_DECIMALS;
        } else if (token == USDT_TOKEN_ADDRESS) {
            return 6;
        } else if (token == DAI_TOKEN_ADDRESS) {
            return 18;
        } else if (token == USDC_TOKEN_ADDRESS) {
            return 6;
        } else if (token == WBTC_TOKEN_ADDRESS) {
            return 8;
        } else if (token == KNC_TOKEN_ADDRESS) {
            return 18;
        } else {
            return 0;
        }
    }

    function minOf(uint256 x, uint256 y) internal pure returns (uint256) {

        return x > y ? y : x;
    }
}



pragma solidity ^0.6.0;

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



pragma solidity ^0.6.2;

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

        return _functionCallWithValue(target, data, 0, errorMessage);
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");
        return _functionCallWithValue(target, data, value, errorMessage);
    }

    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {

        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);
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
}



pragma solidity ^0.6.0;




library SafeERC20 {

    using SafeMath for uint256;
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

        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {


        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) { // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}


pragma solidity 0.6.6;

contract PermissionGroups {

    uint256 internal constant MAX_GROUP_SIZE = 50;

    address public admin;
    address public pendingAdmin;
    mapping(address => bool) internal operators;
    mapping(address => bool) internal alerters;
    address[] internal operatorsGroup;
    address[] internal alertersGroup;

    event AdminClaimed(address newAdmin, address previousAdmin);

    event TransferAdminPending(address pendingAdmin);

    event OperatorAdded(address newOperator, bool isAdd);

    event AlerterAdded(address newAlerter, bool isAdd);

    constructor(address _admin) public {
        require(_admin != address(0), "admin 0");
        admin = _admin;
    }

    modifier onlyAdmin() {

        require(msg.sender == admin, "only admin");
        _;
    }

    modifier onlyOperator() {

        require(operators[msg.sender], "only operator");
        _;
    }

    modifier onlyAlerter() {

        require(alerters[msg.sender], "only alerter");
        _;
    }

    function getOperators() external view returns (address[] memory) {

        return operatorsGroup;
    }

    function getAlerters() external view returns (address[] memory) {

        return alertersGroup;
    }

    function transferAdmin(address newAdmin) public onlyAdmin {

        require(newAdmin != address(0), "new admin 0");
        emit TransferAdminPending(newAdmin);
        pendingAdmin = newAdmin;
    }

    function transferAdminQuickly(address newAdmin) public onlyAdmin {

        require(newAdmin != address(0), "admin 0");
        emit TransferAdminPending(newAdmin);
        emit AdminClaimed(newAdmin, admin);
        admin = newAdmin;
    }

    function claimAdmin() public {

        require(pendingAdmin == msg.sender, "not pending");
        emit AdminClaimed(pendingAdmin, admin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    function addAlerter(address newAlerter) public onlyAdmin {

        require(!alerters[newAlerter], "alerter exists"); // prevent duplicates.
        require(alertersGroup.length < MAX_GROUP_SIZE, "max alerters");

        emit AlerterAdded(newAlerter, true);
        alerters[newAlerter] = true;
        alertersGroup.push(newAlerter);
    }

    function removeAlerter(address alerter) public onlyAdmin {

        require(alerters[alerter], "not alerter");
        alerters[alerter] = false;

        for (uint256 i = 0; i < alertersGroup.length; ++i) {
            if (alertersGroup[i] == alerter) {
                alertersGroup[i] = alertersGroup[alertersGroup.length - 1];
                alertersGroup.pop();
                emit AlerterAdded(alerter, false);
                break;
            }
        }
    }

    function addOperator(address newOperator) public onlyAdmin {

        require(!operators[newOperator], "operator exists"); // prevent duplicates.
        require(operatorsGroup.length < MAX_GROUP_SIZE, "max operators");

        emit OperatorAdded(newOperator, true);
        operators[newOperator] = true;
        operatorsGroup.push(newOperator);
    }

    function removeOperator(address operator) public onlyAdmin {

        require(operators[operator], "not operator");
        operators[operator] = false;

        for (uint256 i = 0; i < operatorsGroup.length; ++i) {
            if (operatorsGroup[i] == operator) {
                operatorsGroup[i] = operatorsGroup[operatorsGroup.length - 1];
                operatorsGroup.pop();
                emit OperatorAdded(operator, false);
                break;
            }
        }
    }
}


pragma solidity 0.6.6;




contract Withdrawable is PermissionGroups {

    using SafeERC20 for IERC20Ext;

    event TokenWithdraw(IERC20Ext token, uint256 amount, address sendTo);
    event EtherWithdraw(uint256 amount, address sendTo);

    constructor(address _admin) public PermissionGroups(_admin) {}

    function withdrawToken(
        IERC20Ext token,
        uint256 amount,
        address sendTo
    ) external onlyAdmin {

        token.safeTransfer(sendTo, amount);
        emit TokenWithdraw(token, amount, sendTo);
    }

    function withdrawEther(uint256 amount, address payable sendTo) external onlyAdmin {

        (bool success, ) = sendTo.call{value: amount}("");
        require(success, "withdraw failed");
        emit EtherWithdraw(amount, sendTo);
    }
}


pragma solidity 0.6.6;








contract KyberFprReserveV2 is IKyberReserve, Utils, Withdrawable {

    using SafeERC20 for IERC20Ext;
    using SafeMath for uint256;

    mapping(bytes32 => bool) public approvedWithdrawAddresses; // sha3(token,address)=>bool
    mapping(address => address) public tokenWallet;

    struct ConfigData {
        bool tradeEnabled;
        bool doRateValidation; // whether to do rate validation in trade func
        uint128 maxGasPriceWei;
    }

    address public kyberNetwork;
    ConfigData internal configData;

    IConversionRates public conversionRatesContract;
    IKyberSanity public sanityRatesContract;
    IWeth public weth;

    event DepositToken(IERC20Ext indexed token, uint256 amount);
    event TradeExecute(
        address indexed origin,
        IERC20Ext indexed src,
        uint256 srcAmount,
        IERC20Ext indexed destToken,
        uint256 destAmount,
        address payable destAddress
    );
    event TradeEnabled(bool enable);
    event MaxGasPriceUpdated(uint128 newMaxGasPrice);
    event DoRateValidationUpdated(bool doRateValidation);
    event WithdrawAddressApproved(IERC20Ext indexed token, address indexed addr, bool approve);
    event NewTokenWallet(IERC20Ext indexed token, address indexed wallet);
    event WithdrawFunds(IERC20Ext indexed token, uint256 amount, address indexed destination);
    event SetKyberNetworkAddress(address indexed network);
    event SetConversionRateAddress(IConversionRates indexed rate);
    event SetWethAddress(IWeth indexed weth);
    event SetSanityRateAddress(IKyberSanity indexed sanity);

    constructor(
        address _kyberNetwork,
        IConversionRates _ratesContract,
        IWeth _weth,
        uint128 _maxGasPriceWei,
        bool _doRateValidation,
        address _admin
    ) public Withdrawable(_admin) {
        require(_kyberNetwork != address(0), "kyberNetwork 0");
        require(_ratesContract != IConversionRates(0), "ratesContract 0");
        require(_weth != IWeth(0), "weth 0");
        kyberNetwork = _kyberNetwork;
        conversionRatesContract = _ratesContract;
        weth = _weth;
        configData = ConfigData({
            tradeEnabled: true,
            maxGasPriceWei: _maxGasPriceWei,
            doRateValidation: _doRateValidation
        });
    }

    receive() external payable {
        emit DepositToken(ETH_TOKEN_ADDRESS, msg.value);
    }

    function trade(
        IERC20Ext srcToken,
        uint256 srcAmount,
        IERC20Ext destToken,
        address payable destAddress,
        uint256 conversionRate,
        bool /* validate */
    ) external override payable returns (bool) {

        require(msg.sender == kyberNetwork, "wrong sender");
        ConfigData memory data = configData;
        require(data.tradeEnabled, "trade not enable");
        require(tx.gasprice <= uint256(data.maxGasPriceWei), "gas price too high");

        doTrade(
            srcToken,
            srcAmount,
            destToken,
            destAddress,
            conversionRate,
            data.doRateValidation
        );

        return true;
    }

    function enableTrade() external onlyAdmin {

        configData.tradeEnabled = true;
        emit TradeEnabled(true);
    }

    function disableTrade() external onlyAlerter {

        configData.tradeEnabled = false;
        emit TradeEnabled(false);
    }

    function setMaxGasPrice(uint128 newMaxGasPrice) external onlyOperator {

        configData.maxGasPriceWei = newMaxGasPrice;
        emit MaxGasPriceUpdated(newMaxGasPrice);
    }

    function setDoRateValidation(bool _doRateValidation) external onlyAdmin {

        configData.doRateValidation = _doRateValidation;
        emit DoRateValidationUpdated(_doRateValidation);
    }

    function approveWithdrawAddress(
        IERC20Ext token,
        address addr,
        bool approve
    ) external onlyAdmin {

        approvedWithdrawAddresses[keccak256(abi.encodePacked(address(token), addr))] = approve;
        getSetDecimals(token);
        emit WithdrawAddressApproved(token, addr, approve);
    }

    function setTokenWallet(IERC20Ext token, address wallet) external onlyAdmin {

        tokenWallet[address(token)] = wallet;
        getSetDecimals(token);
        emit NewTokenWallet(token, wallet);
    }

    function withdraw(
        IERC20Ext token,
        uint256 amount,
        address destination
    ) external onlyOperator {

        require(
            approvedWithdrawAddresses[keccak256(abi.encodePacked(address(token), destination))],
            "destination is not approved"
        );

        if (token == ETH_TOKEN_ADDRESS) {
            (bool success, ) = destination.call{value: amount}("");
            require(success, "withdraw eth failed");
        } else {
            address wallet = getTokenWallet(token);
            if (wallet == address(this)) {
                token.safeTransfer(destination, amount);
            } else {
                token.safeTransferFrom(wallet, destination, amount);
            }
        }

        emit WithdrawFunds(token, amount, destination);
    }

    function setKyberNetwork(address _newNetwork) external onlyAdmin {

        require(_newNetwork != address(0), "kyberNetwork 0");
        kyberNetwork = _newNetwork;
        emit SetKyberNetworkAddress(_newNetwork);
    }

    function setConversionRate(IConversionRates _newConversionRate) external onlyAdmin {

        require(_newConversionRate != IConversionRates(0), "conversionRates 0");
        conversionRatesContract = _newConversionRate;
        emit SetConversionRateAddress(_newConversionRate);
    }

    function setWeth(IWeth _newWeth) external onlyAdmin {

        require(_newWeth != IWeth(0), "weth 0");
        weth = _newWeth;
        emit SetWethAddress(_newWeth);
    }

    function setSanityRate(IKyberSanity _newSanity) external onlyAdmin {

        sanityRatesContract = _newSanity;
        emit SetSanityRateAddress(_newSanity);
    }

    function getConversionRate(
        IERC20Ext src,
        IERC20Ext dest,
        uint256 srcQty,
        uint256 blockNumber
    ) external override view returns (uint256) {

        ConfigData memory data = configData;
        if (!data.tradeEnabled) return 0;
        if (tx.gasprice > uint256(data.maxGasPriceWei)) return 0;
        if (srcQty == 0) return 0;

        IERC20Ext token;
        bool isBuy;

        if (ETH_TOKEN_ADDRESS == src) {
            isBuy = true;
            token = dest;
        } else if (ETH_TOKEN_ADDRESS == dest) {
            isBuy = false;
            token = src;
        } else {
            return 0; // pair is not listed
        }

        uint256 rate;
        try conversionRatesContract.getRate(token, blockNumber, isBuy, srcQty) returns(uint256 r) {
            rate = r;
        } catch {
            return 0;
        }
        uint256 destQty = calcDestAmount(src, dest, srcQty, rate);

        if (getBalance(dest) < destQty) return 0;

        if (sanityRatesContract != IKyberSanity(0)) {
            uint256 sanityRate = sanityRatesContract.getSanityRate(src, dest);
            if (rate > sanityRate) return 0;
        }

        return rate;
    }

    function isAddressApprovedForWithdrawal(IERC20Ext token, address addr)
        external
        view
        returns (bool)
    {

        return approvedWithdrawAddresses[keccak256(abi.encodePacked(address(token), addr))];
    }

    function tradeEnabled() external view returns (bool) {

        return configData.tradeEnabled;
    }

    function maxGasPriceWei() external view returns (uint128) {

        return configData.maxGasPriceWei;
    }

    function doRateValidation() external view returns (bool) {

        return configData.doRateValidation;
    }

    function getBalance(IERC20Ext token) public view returns (uint256) {

        address wallet = getTokenWallet(token);
        IERC20Ext usingToken;

        if (token == ETH_TOKEN_ADDRESS) {
            if (wallet == address(this)) {
                return address(this).balance;
            }
            usingToken = weth;
        } else {
            if (wallet == address(this)) {
                return token.balanceOf(address(this));
            }
            usingToken = token;
        }

        uint256 balanceOfWallet = usingToken.balanceOf(wallet);
        uint256 allowanceOfWallet = usingToken.allowance(wallet, address(this));

        return minOf(balanceOfWallet, allowanceOfWallet);
    }

    function getTokenWallet(IERC20Ext token) public view returns (address wallet) {

        wallet = (token == ETH_TOKEN_ADDRESS)
            ? tokenWallet[address(weth)]
            : tokenWallet[address(token)];
        if (wallet == address(0)) {
            wallet = address(this);
        }
    }

    function doTrade(
        IERC20Ext srcToken,
        uint256 srcAmount,
        IERC20Ext destToken,
        address payable destAddress,
        uint256 conversionRate,
        bool validateRate
    ) internal {

        require(conversionRate > 0, "rate is 0");

        bool isBuy = srcToken == ETH_TOKEN_ADDRESS;
        if (isBuy) {
            require(msg.value == srcAmount, "wrong msg value");
        } else {
            require(msg.value == 0, "bad msg value");
        }

        if (validateRate) {
            uint256 rate = conversionRatesContract.getRate(
                isBuy ? destToken : srcToken,
                block.number,
                isBuy,
                srcAmount
            );
            require(rate >= conversionRate, "reserve rate lower then network requested rate");
            if (sanityRatesContract != IKyberSanity(0)) {
                uint256 sanityRate = sanityRatesContract.getSanityRate(srcToken, destToken);
                require(rate <= sanityRate, "rate should not be greater than sanity rate" );
            }
        }

        uint256 destAmount = calcDestAmount(srcToken, destToken, srcAmount, conversionRate);
        require(destAmount > 0, "dest amount is 0");

        address srcTokenWallet = getTokenWallet(srcToken);
        address destTokenWallet = getTokenWallet(destToken);

        if (isBuy) {
            conversionRatesContract.recordImbalance(
                destToken,
                int256(destAmount),
                0,
                block.number
            );
            if (srcTokenWallet != address(this)) {
                weth.deposit{value: msg.value}();
                IERC20Ext(weth).safeTransfer(srcTokenWallet, msg.value);
            }
            if (destTokenWallet == address(this)) {
                destToken.safeTransfer(destAddress, destAmount);
            } else {
                destToken.safeTransferFrom(destTokenWallet, destAddress, destAmount);
            }
        } else {
            conversionRatesContract.recordImbalance(
                srcToken,
                -1 * int256(srcAmount),
                0,
                block.number
            );
            srcToken.safeTransferFrom(msg.sender, srcTokenWallet, srcAmount);
            if (destTokenWallet != address(this)) {
                IERC20Ext(weth).safeTransferFrom(destTokenWallet, address(this), destAmount);
                weth.withdraw(destAmount);
            }
            (bool success, ) = destAddress.call{value: destAmount}("");
            require(success, "transfer eth from reserve to destAddress failed");
        }

        emit TradeExecute(msg.sender, srcToken, srcAmount, destToken, destAmount, destAddress);
    }
}