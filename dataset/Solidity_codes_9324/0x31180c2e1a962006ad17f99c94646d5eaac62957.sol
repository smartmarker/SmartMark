
pragma solidity 0.5.11;

interface ERC20 {

    function totalSupply() external view returns (uint supply);

    function balanceOf(address _owner) external view returns (uint balance);

    function transfer(address _to, uint _value) external returns (bool success);

    function transferFrom(address _from, address _to, uint _value) external returns (bool success);

    function approve(address _spender, uint _value) external returns (bool success);

    function allowance(address _owner, address _spender) external view returns (uint remaining);

    function decimals() external view returns(uint digits);

    event Approval(address indexed _owner, address indexed _spender, uint _value);
}


contract OtcInterface {

    function getOffer(uint id) external view returns (uint, ERC20, uint, ERC20);

    function getBestOffer(ERC20 sellGem, ERC20 buyGem) external view returns(uint);

    function getWorseOffer(uint id) external view returns(uint);

    function take(bytes32 id, uint128 maxTakeAmount) external;

}


contract WethInterface is ERC20 {

    function deposit() public payable;

    function withdraw(uint) public;

}

interface KyberReserveInterface {


    function trade(
        ERC20 srcToken,
        uint srcAmount,
        ERC20 destToken,
        address payable destAddress,
        uint conversionRate,
        bool validate
    )
        external
        payable
        returns(bool);


    function getConversionRate(ERC20 src, ERC20 dest, uint srcQty, uint blockNumber) external view returns(uint);

}


contract PermissionGroups {


    address public admin;
    address public pendingAdmin;
    mapping(address=>bool) internal operators;
    mapping(address=>bool) internal alerters;
    address[] internal operatorsGroup;
    address[] internal alertersGroup;
    uint constant internal MAX_GROUP_SIZE = 50;

    constructor() public {
        admin = msg.sender;
    }

    modifier onlyAdmin() {

        require(msg.sender == admin);
        _;
    }

    modifier onlyOperator() {

        require(operators[msg.sender]);
        _;
    }

    modifier onlyAlerter() {

        require(alerters[msg.sender]);
        _;
    }

    function getOperators () external view returns(address[] memory) {
        return operatorsGroup;
    }

    function getAlerters () external view returns(address[] memory) {
        return alertersGroup;
    }

    event TransferAdminPending(address pendingAdmin);

    function transferAdmin(address newAdmin) public onlyAdmin {

        require(newAdmin != address(0));
        emit TransferAdminPending(pendingAdmin);
        pendingAdmin = newAdmin;
    }

    function transferAdminQuickly(address newAdmin) public onlyAdmin {

        require(newAdmin != address(0));
        emit TransferAdminPending(newAdmin);
        emit AdminClaimed(newAdmin, admin);
        admin = newAdmin;
    }

    event AdminClaimed( address newAdmin, address previousAdmin);

    function claimAdmin() public {

        require(pendingAdmin == msg.sender);
        emit AdminClaimed(pendingAdmin, admin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    event AlerterAdded (address newAlerter, bool isAdd);

    function addAlerter(address newAlerter) public onlyAdmin {

        require(!alerters[newAlerter]); // prevent duplicates.
        require(alertersGroup.length < MAX_GROUP_SIZE);

        emit AlerterAdded(newAlerter, true);
        alerters[newAlerter] = true;
        alertersGroup.push(newAlerter);
    }

    function removeAlerter (address alerter) public onlyAdmin {
        require(alerters[alerter]);
        alerters[alerter] = false;

        for (uint i = 0; i < alertersGroup.length; ++i) {
            if (alertersGroup[i] == alerter) {
                alertersGroup[i] = alertersGroup[alertersGroup.length - 1];
                alertersGroup.length--;
                emit AlerterAdded(alerter, false);
                break;
            }
        }
    }

    event OperatorAdded(address newOperator, bool isAdd);

    function addOperator(address newOperator) public onlyAdmin {

        require(!operators[newOperator]); // prevent duplicates.
        require(operatorsGroup.length < MAX_GROUP_SIZE);

        emit OperatorAdded(newOperator, true);
        operators[newOperator] = true;
        operatorsGroup.push(newOperator);
    }

    function removeOperator (address operator) public onlyAdmin {
        require(operators[operator]);
        operators[operator] = false;

        for (uint i = 0; i < operatorsGroup.length; ++i) {
            if (operatorsGroup[i] == operator) {
                operatorsGroup[i] = operatorsGroup[operatorsGroup.length - 1];
                operatorsGroup.length -= 1;
                emit OperatorAdded(operator, false);
                break;
            }
        }
    }
}

contract Withdrawable is PermissionGroups {


    event TokenWithdraw(ERC20 token, uint amount, address sendTo);

    function withdrawToken(ERC20 token, uint amount, address sendTo) external onlyAdmin {

        require(token.transfer(sendTo, amount));
        emit TokenWithdraw(token, amount, sendTo);
    }

    event EtherWithdraw(uint amount, address sendTo);

    function withdrawEther(uint amount, address payable sendTo) external onlyAdmin {

        sendTo.transfer(amount);
        emit EtherWithdraw(amount, sendTo);
    }
}


contract Eth2DaiReserve is KyberReserveInterface, Withdrawable {


    uint constant POW_2_32 = 2 ** 32;
    uint constant POW_2_96 = 2 ** 96;
    uint constant BASIC_FACTOR_STEP = 100000;

    uint constant internal MAX_QTY = (10**28); // 10B tokens
    uint constant internal MAX_RATE = (PRECISION * 10**6); // up to 1M tokens per ETH
    uint constant internal PRECISION = 10**18;
    uint constant internal INVALID_ID = uint(-1);
    uint constant internal COMMON_DECIMALS = 18;
    ERC20 constant internal ETH_TOKEN_ADDRESS = ERC20(0x00eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee);

    address public kyberNetwork;
    bool public tradeEnabled;
    uint public feeBps;

    OtcInterface public otc = OtcInterface(0x39755357759cE0d7f32dC8dC45414CCa409AE24e);
    WethInterface public wethToken = WethInterface(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    ERC20 public DAIToken = ERC20(0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359);

    mapping(address => bool) public isTokenListed;
    mapping(address => uint) internalInventoryData;
    mapping(address => uint) tokenBasicData;
    mapping(address => uint) tokenFactorData;

    struct BasicDataConfig {
        uint minETHSupport;
        uint maxTraverse;
        uint maxTakes;
    }

    struct FactorDataConfig {
        uint maxTraverseX;
        uint maxTraverseY;
        uint maxTakeX;
        uint maxTakeY;
        uint minOrderSizeX;
        uint minOrderSizeY;
    }

    struct InternalInventoryData {
        uint minTokenBal;
        uint maxTokenBal;
        uint premiumBps;
        uint minSpreadBps;
    }

    struct OfferData {
        uint payAmount;
        uint buyAmount;
        uint id;
    }

    constructor(address _kyberNetwork, uint _feeBps, address _admin) public {
        require(_kyberNetwork != address(0), "constructor: kyberNetwork's address is missing");
        require(_feeBps < 10000, "constructor: fee >= 10000");
        require(_admin != address(0), "constructor: admin is missing");
        require(getDecimals(wethToken) == COMMON_DECIMALS, "constructor: wethToken's decimals is not COMMON_DECIMALS");
        require(wethToken.approve(address(otc), 2**255), "constructor: failed to approve otc (wethToken)");
    
        kyberNetwork = _kyberNetwork;
        feeBps = _feeBps;
        admin = _admin;
        tradeEnabled = true;
    }

    function() external payable {
    }

    function getConversionRate(ERC20 src, ERC20 dest, uint srcQty, uint) public view returns(uint) {

        if (!tradeEnabled) { return 0; }
        ERC20 token = src == ETH_TOKEN_ADDRESS ? dest : src;
        if (!isTokenListed[address(token)]) { return 0; }
        
        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(token);

        if (token == src && !checkValidSpread(bid, ask, false, 0)) { return 0; }

        uint destAmount;
        OfferData[] memory offers;

        uint srcAmount = srcQty == 0 ? 1 : srcQty;

        if (src == ETH_TOKEN_ADDRESS) {
            (destAmount, offers) = findBestOffers(dest, wethToken, srcAmount, bid, ask);
        } else {
            (destAmount, offers) = findBestOffers(wethToken, src, srcAmount, bid, ask);
        }

        if (offers.length == 0 || destAmount == 0) { return 0; } // no offer or destAmount == 0, return 0 for rate

        uint rate = calcRateFromQty(srcAmount, destAmount, COMMON_DECIMALS, COMMON_DECIMALS);

        bool useInternalInventory;
        uint premiumBps;

        if (src == ETH_TOKEN_ADDRESS) {
            (useInternalInventory, premiumBps) = shouldUseInternalInventory(dest,
                                                                            destAmount,
                                                                            srcAmount,
                                                                            true,
                                                                            bid,
                                                                            ask
                                                                            );
        } else {
            (useInternalInventory, premiumBps) = shouldUseInternalInventory(src,
                                                                            srcAmount,
                                                                            destAmount,
                                                                            false,
                                                                            bid,
                                                                            ask
                                                                            );
        }

        if (useInternalInventory) {
            rate = valueAfterAddingPremium(rate, premiumBps);
        } else {
            rate = valueAfterReducingFee(rate);
        }

        return applyInternalInventoryHintToRate(rate, useInternalInventory);
    }

    event TradeExecute(
        address indexed origin,
        address src,
        uint srcAmount,
        address destToken,
        uint destAmount,
        address payable destAddress
    );

    function trade(
        ERC20 srcToken,
        uint srcAmount,
        ERC20 destToken,
        address payable destAddress,
        uint conversionRate,
        bool validate
    )
        public
        payable
        returns(bool)
    {

        require(tradeEnabled, "trade: tradeEnabled is false");
        require(msg.sender == kyberNetwork, "trade: not call from kyberNetwork's contract");
        require(srcToken == ETH_TOKEN_ADDRESS || destToken == ETH_TOKEN_ADDRESS, "trade: srcToken or destToken must be ETH");

        ERC20 token = srcToken == ETH_TOKEN_ADDRESS ? destToken : srcToken;
        require(isTokenListed[address(token)], "trade: token is not listed");

        require(doTrade(srcToken, srcAmount, destToken, destAddress, conversionRate, validate), "trade: doTrade returns false");
        return true;
    }

    function doTrade(
        ERC20 srcToken,
        uint srcAmount,
        ERC20 destToken,
        address payable destAddress,
        uint conversionRate,
        bool validate
    )
        internal
        returns(bool)
    {

        if (validate) {
            require(conversionRate > 0, "doTrade: conversionRate is 0");
            if (srcToken == ETH_TOKEN_ADDRESS)
                require(msg.value == srcAmount, "doTrade: msg.value != srcAmount");
            else
                require(msg.value == 0, "doTrade: msg.value must be 0");
        }

        uint userExpectedDestAmount = calcDstQty(srcAmount, COMMON_DECIMALS, COMMON_DECIMALS, conversionRate);
        require(userExpectedDestAmount > 0, "doTrade: userExpectedDestAmount == 0"); // sanity check

        uint actualDestAmount;

        bool useInternalInventory = conversionRate % 2 == 1;

        if (useInternalInventory) {
            if (srcToken == ETH_TOKEN_ADDRESS) {
                require(destToken.transfer(destAddress, userExpectedDestAmount), "doTrade: (useInternalInventory) can not transfer back token");
            } else {
                require(srcToken.transferFrom(msg.sender, address(this), srcAmount), "doTrade: (useInternalInventory) can not collect src token");
                destAddress.transfer(userExpectedDestAmount);
            }

            emit TradeExecute(msg.sender, address(srcToken), srcAmount, address(destToken), userExpectedDestAmount, destAddress);
            return true;
        }

        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(srcToken == ETH_TOKEN_ADDRESS ? destToken : srcToken);

        OfferData [] memory offers;
        if (srcToken == ETH_TOKEN_ADDRESS) {
            (actualDestAmount, offers) = findBestOffers(destToken, wethToken, srcAmount, bid, ask);   
        } else {
            (actualDestAmount, offers) = findBestOffers(wethToken, srcToken, srcAmount, bid, ask);
        }

        require(actualDestAmount >= userExpectedDestAmount , "doTrade: actualDestAmount is less than userExpectedDestAmount");

        if (srcToken == ETH_TOKEN_ADDRESS) {
            wethToken.deposit.value(msg.value)();
            actualDestAmount = takeMatchingOrders(destToken, srcAmount, offers);
            require(actualDestAmount >= userExpectedDestAmount, "doTrade: actualDestAmount is less than userExpectedDestAmount, eth to token");
            require(destToken.transfer(destAddress, userExpectedDestAmount), "doTrade: can not transfer back requested token");
        } else {
            require(srcToken.transferFrom(msg.sender, address(this), srcAmount), "doTrade: can not collect src token");
            actualDestAmount = takeMatchingOrders(wethToken, srcAmount, offers);
            require(actualDestAmount >= userExpectedDestAmount, "doTrade: actualDestAmount is less than userExpectedDestAmount, token to eth");
            wethToken.withdraw(actualDestAmount);
            destAddress.transfer(userExpectedDestAmount);
        }

        emit TradeExecute(msg.sender, address(srcToken), srcAmount, address(destToken), userExpectedDestAmount, destAddress);
        return true;
    }

    function takeMatchingOrders(ERC20 destToken, uint srcAmount, OfferData[] memory offers) internal returns(uint actualDestAmount) {

        require(destToken != ETH_TOKEN_ADDRESS, "takeMatchingOrders: destToken is ETH");

        uint lastReserveBalance = destToken.balanceOf(address(this));
        uint remainingSrcAmount = srcAmount;

        for(uint i = 0; i < offers.length; i++) {
            if (offers[i].id == 0 || remainingSrcAmount == 0) { break; }

            uint payAmount = minOf(remainingSrcAmount, offers[i].payAmount);
            uint buyAmount = payAmount * offers[i].buyAmount / offers[i].payAmount;

            otc.take(bytes32(offers[i].id), uint128(buyAmount));
            remainingSrcAmount -= payAmount;
        }

        require(remainingSrcAmount == 0, "takeMatchingOrders: did not take all src amount");

        uint newReserveBalance = destToken.balanceOf(address(this));

        require(newReserveBalance > lastReserveBalance, "takeMatchingOrders: newReserveBalance <= lastReserveBalance");

        actualDestAmount = newReserveBalance - lastReserveBalance;
    }

    function shouldUseInternalInventory(ERC20 token,
                                        uint tokenVal,
                                        uint ethVal,
                                        bool ethToToken,
                                        OfferData memory bid,
                                        OfferData memory ask)
        internal
        view
        returns(bool shouldUse, uint premiumBps)
    {

        require(tokenVal <= MAX_QTY, "shouldUseInternalInventory: tokenVal > MAX_QTY");

        InternalInventoryData memory inventoryData = getInternalInventoryData(token);

        shouldUse = false;
        premiumBps = inventoryData.premiumBps;

        uint tokenBalance = token.balanceOf(address(this));

        if (ethToToken) {
            if (tokenBalance < tokenVal) { return (shouldUse, premiumBps); }
            if (tokenVal - tokenVal < inventoryData.minTokenBal) { return (shouldUse, premiumBps); }
        } else {
            if (address(this).balance < ethVal) { return (shouldUse, premiumBps); }
            if (tokenBalance + tokenVal > inventoryData.maxTokenBal) { return (shouldUse, premiumBps); }
        }

        if (!checkValidSpread(bid, ask, true, inventoryData.minSpreadBps)) {
            return (shouldUse, premiumBps);
        }

        shouldUse = true;
    }

    function applyInternalInventoryHintToRate(
        uint rate,
        bool useInternalInventory
    )
        internal
        pure
        returns(uint)
    {

        return rate % 2 == (useInternalInventory ? 1 : 0)
            ? rate
            : rate - 1;
    }

    function valueAfterReducingFee(uint val) public view returns(uint) {

        require(val <= MAX_QTY, "valueAfterReducingFee: val > MAX_QTY");
        return ((10000 - feeBps) * val) / 10000;
    }

    function valueAfterAddingPremium(uint val, uint premium) public pure returns(uint) {

        require(val <= MAX_QTY, "valueAfterAddingPremium: val > MAX_QTY");
        return val * (10000 + premium) / 10000;
    }

    event TokenConfigDataSet(
        ERC20 token, uint maxTraverse, uint traveseFactorX, uint traveseFactorY,
        uint maxTake, uint takeFactorX, uint takeFactorY,
        uint minSizeFactorX, uint minSizeFactorY, uint minETHSupport
    );

    function setTokenConfigData(
        ERC20 token, uint maxTraverse, uint traveseFactorX, uint traveseFactorY,
        uint maxTake, uint takeFactorX, uint takeFactorY,
        uint minSizeFactorX, uint minSizeFactorY, uint minETHSupport) public {

        address tokenAddr = address(token);
        require(isTokenListed[tokenAddr]);
        tokenBasicData[tokenAddr] = encodeTokenBasicData(minETHSupport, maxTraverse, maxTake);
        tokenFactorData[tokenAddr] = encodeFactorData(
            traveseFactorX,
            traveseFactorY,
            takeFactorX,
            takeFactorY,
            minSizeFactorX,
            minSizeFactorY
        );
        emit TokenConfigDataSet(
            token, maxTraverse, traveseFactorX, takeFactorY,
            maxTake, takeFactorX, takeFactorY,
            minSizeFactorX, minSizeFactorY, minETHSupport
        );
    }

    event TradeEnabled(bool enable);

    function enableTrade() public onlyAdmin returns(bool) {

        tradeEnabled = true;
        emit TradeEnabled(true);

        return true;
    }

    function disableTrade() public onlyAlerter returns(bool) {

        tradeEnabled = false;
        emit TradeEnabled(false);

        return true;
    }

    event KyberNetworkSet(address kyberNetwork);

    function setKyberNetwork(address _kyberNetwork) public onlyAdmin {

        require(_kyberNetwork != address(0), "setKyberNetwork: kyberNetwork's address is missing");

        kyberNetwork = _kyberNetwork;
        emit KyberNetworkSet(kyberNetwork);
    }

    event InternalInventoryDataSet(uint minToken, uint maxToken, uint pricePremiumBps, uint minSpreadBps);

    function setInternalInventoryData(ERC20 token, uint minToken, uint maxToken, uint pricePremiumBps, uint minSpreadBps) public onlyAdmin {

        require(isTokenListed[address(token)], "setInternalInventoryData: token is not listed");
        require(minToken < POW_2_96, "setInternalInventoryData: minToken > 2**96");
        require(maxToken < POW_2_96, "setInternalInventoryData: maxToken > 2**96");
        require(pricePremiumBps < POW_2_32, "setInternalInventoryData: pricePremiumBps > 2**32");
        require(minSpreadBps < POW_2_32, "setInternalInventoryData: minSpreadBps > 2**32");
        require(2 * minSpreadBps >= (feeBps + pricePremiumBps), "setInternalInventoryData: minSpreadBps should be >= (feeBps + pricePremiumBps)/2");

        internalInventoryData[address(token)] = encodeInternalInventoryData(minToken, maxToken, pricePremiumBps, minSpreadBps);

        emit InternalInventoryDataSet(minToken, maxToken, pricePremiumBps, minSpreadBps);
    }

    event TokenListed(ERC20 token);

    function listToken(ERC20 token) public onlyAdmin {

        address tokenAddr = address(token);

        require(tokenAddr != address(0), "listToken: token's address is missing");
        require(!isTokenListed[tokenAddr], "listToken: token's alr listed");
        require(getDecimals(token) == COMMON_DECIMALS, "listToken: token's decimals is not COMMON_DECIMALS");
        require(token.approve(address(otc), 2**255), "listToken: approve token otc failed");

        isTokenListed[tokenAddr] = true;

        emit TokenListed(token);
    }

    event TokenDelisted(ERC20 token);

    function delistToken(ERC20 token) public onlyAdmin {

        address tokenAddr = address(token);

        require(isTokenListed[tokenAddr], "delistToken: token is not listed");
        require(token.approve(address(otc), 0), "delistToken: reset approve token failed");

        delete isTokenListed[tokenAddr];
        delete internalInventoryData[tokenAddr];
        delete tokenFactorData[tokenAddr];
        delete tokenBasicData[tokenAddr];

        emit TokenDelisted(token);
    }

    event FeeBpsSet(uint feeBps);

    function setFeeBps(uint _feeBps) public onlyAdmin {

        require(_feeBps < 10000, "setFeeBps: feeBps >= 10000");

        feeBps = _feeBps;
        emit FeeBpsSet(feeBps);
    }

    function showBestOffers(ERC20 token, bool isEthToToken, uint srcAmountToken) public view
        returns(uint destAmount, uint destAmountToken, uint [] memory offerIds) 
    {

        OfferData [] memory offers;
        ERC20 dstToken = isEthToToken ? token : wethToken;
        ERC20 srcToken = isEthToToken ? wethToken : token;

        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(token);

        (destAmount, offers) = findBestOffers(dstToken, srcToken, (srcAmountToken * 10 ** 18), bid, ask);
        
        destAmountToken = destAmount / 10 ** 18;
        
        uint i;
        for (i; i < offers.length; i++) {
            if (offers[i].id == 0) {
                break;
            }
        }
    
        offerIds = new uint[](i);
        for (i = 0; i < offerIds.length; i++) {
            offerIds[i] = offers[i].id;
        }
    }    
    
    function findBestOffers(ERC20 dstToken, ERC20 srcToken, uint srcAmount, OfferData memory bid, OfferData memory ask)
        internal view
        returns(uint totalDestAmount, OfferData [] memory offers)
    {

        uint remainingSrcAmount = srcAmount;
        uint maxOrdersToTake;
        uint maxTraversedOrders;
        uint minPayAmount;
        uint numTakenOffer = 0;
        totalDestAmount = 0;
        ERC20 token = srcToken == wethToken ? dstToken : srcToken;

        (maxOrdersToTake, maxTraversedOrders, minPayAmount) = calcOfferLimitsFromFactorData(
            token,
            (srcToken == wethToken),
            bid,
            ask,
            srcAmount
        );

        offers = new OfferData[](maxTraversedOrders);

        if (maxTraversedOrders == 0 || maxOrdersToTake == 0) {
            return (totalDestAmount, offers);
        }

        if ((srcToken == wethToken && bid.id == 0) || (dstToken == wethToken && ask.id == 0)) {
            offers[0].id = otc.getBestOffer(dstToken, srcToken);
            (offers[0].buyAmount, , offers[0].payAmount, ) = otc.getOffer(offers[0].id);
        } else {
            offers[0] = srcToken == wethToken ? bid : ask;
        }

        if (remainingSrcAmount == 0) { return (totalDestAmount, offers); }

        uint thisOffer;

        OfferData memory biggestSkippedOffer = OfferData(0, 0, 0);

        for ( ;maxTraversedOrders > 0 ; --maxTraversedOrders) {
            thisOffer = numTakenOffer;

            if (biggestSkippedOffer.payAmount >= remainingSrcAmount) {
                offers[numTakenOffer].id = biggestSkippedOffer.id;
                offers[numTakenOffer].buyAmount = remainingSrcAmount * biggestSkippedOffer.buyAmount / biggestSkippedOffer.payAmount;
                offers[numTakenOffer].payAmount = remainingSrcAmount;
                totalDestAmount += offers[numTakenOffer].buyAmount;
                ++numTakenOffer;
                remainingSrcAmount = 0;
                break;
            } else if (offers[numTakenOffer].payAmount >= remainingSrcAmount) {
                offers[numTakenOffer].buyAmount = remainingSrcAmount * offers[numTakenOffer].buyAmount / offers[numTakenOffer].payAmount;
                offers[numTakenOffer].payAmount = remainingSrcAmount;
                totalDestAmount += offers[numTakenOffer].buyAmount;
                ++numTakenOffer;
                remainingSrcAmount = 0;
                break;
            } else if ((maxOrdersToTake - numTakenOffer) > 1
                        && offers[numTakenOffer].payAmount >= minPayAmount) {
                totalDestAmount += offers[numTakenOffer].buyAmount;
                remainingSrcAmount -= offers[numTakenOffer].payAmount;
                ++numTakenOffer;
            } else if (offers[numTakenOffer].payAmount > biggestSkippedOffer.payAmount) {
                biggestSkippedOffer.payAmount = offers[numTakenOffer].payAmount;
                biggestSkippedOffer.buyAmount = offers[numTakenOffer].buyAmount;
                biggestSkippedOffer.id = offers[numTakenOffer].id;
            }

            offers[numTakenOffer].id = otc.getWorseOffer(offers[thisOffer].id);
            (offers[numTakenOffer].buyAmount, , offers[numTakenOffer].payAmount, ) = otc.getOffer(offers[numTakenOffer].id);
        }

        if (remainingSrcAmount > 0) totalDestAmount = 0;
        if (totalDestAmount == 0) offers = new OfferData[](0);
    }

    function calcOfferLimitsFromFactorDataPub(ERC20 token, bool isEthToToken, uint sellTokenSrcAmt, uint sellTokenDstAmt, uint srcAmount)
        public view
        returns(uint maxTakes, uint maxTraverse, uint minPayAmount)
    {

        (maxTakes, maxTraverse, minPayAmount) = calcOfferLimitsFromFactorData(
            token,
            isEthToToken,
            OfferData(0, sellTokenDstAmt, sellTokenSrcAmt),
            OfferData(0, sellTokenSrcAmt, sellTokenDstAmt),
            srcAmount
        );
    }

    function calcOfferLimitsFromFactorDataPub2(ERC20 token, bool isEthToToken, uint srcAmount)
        public view
        returns(uint maxTakes, uint maxTraverse, uint minPayAmount)
    {

        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(token);
        (maxTakes, maxTraverse, minPayAmount) = calcOfferLimitsFromFactorData(
            token,
            isEthToToken,
            bid,
            ask,
            srcAmount
        );
    }

    function calcOfferLimitsFromFactorData(ERC20 token, bool isEthToToken, OfferData memory bid, OfferData memory ask, uint srcAmount)
        internal view
        returns(uint maxTakes, uint maxTraverse, uint minPayAmount)
    {

        if (!isEthToToken && (ask.id == 0 || bid.id == 0)) {
            maxTakes = 0;
            maxTraverse = 0;
            minPayAmount = 0;
            return (maxTakes, maxTraverse, minPayAmount);
        }

        uint order0Pay = 0;
        uint order0Buy = 0;

        if (!isEthToToken) {
            order0Pay = ask.payAmount;
            order0Buy = (ask.buyAmount + ask.payAmount * bid.payAmount / bid.buyAmount) / 2;
        }

        uint ethOrderSize = isEthToToken ? srcAmount : srcAmount * order0Buy / order0Pay;

        BasicDataConfig memory basicData = getTokenBasicData(token);

        if (basicData.minETHSupport > ethOrderSize) {
            maxTakes = 0;
            maxTraverse = 0;
            minPayAmount = 0;
            return (maxTakes, maxTraverse, minPayAmount);
        }

        FactorDataConfig memory factorData = getFactorData(token);

        maxTraverse = (factorData.maxTraverseX * ethOrderSize / PRECISION + factorData.maxTraverseY) / BASIC_FACTOR_STEP;
        maxTraverse = minOf(maxTraverse, basicData.maxTraverse);

        maxTakes = (factorData.maxTakeX * ethOrderSize / PRECISION + factorData.maxTakeY) / BASIC_FACTOR_STEP;
        maxTakes = minOf(maxTakes, basicData.maxTakes);

        uint minETHAmount = (factorData.minOrderSizeX * ethOrderSize + factorData.minOrderSizeY * PRECISION) / BASIC_FACTOR_STEP;

        minPayAmount = isEthToToken ? minETHAmount : minETHAmount * order0Pay / order0Buy;
    }

    function getFirstOffer(ERC20 offerSellGem, ERC20 offerBuyGem)
        public view
        returns(uint offerId, uint offerPayAmount, uint offerBuyAmount)
    {

        offerId = otc.getBestOffer(offerSellGem, offerBuyGem);
        (offerBuyAmount, ,offerPayAmount, ) = otc.getOffer(offerId);
    }

    function getNextBestOffer(
        ERC20 offerSellGem,
        ERC20 offerBuyGem,
        uint payAmount,
        uint prevOfferId
    )
        public
        view
        returns(
            uint offerId,
            uint offerPayAmount,
            uint offerBuyAmount
        )
    {

        if (prevOfferId == INVALID_ID) {
            offerId = otc.getBestOffer(offerSellGem, offerBuyGem);
        } else {
            offerId = otc.getWorseOffer(prevOfferId);
        }

        (offerBuyAmount, ,offerPayAmount, ) = otc.getOffer(offerId);

        while (payAmount > offerPayAmount) {
            offerId = otc.getWorseOffer(offerId); // next best offer
            if (offerId == 0) {
                offerId = 0;
                offerPayAmount = 0;
                offerBuyAmount = 0;
                break;
            }
            (offerBuyAmount, ,offerPayAmount, ) = otc.getOffer(offerId);
        }
    }
    
    function getEthToDaiOrders(uint numOrders) public view
        returns(uint [] memory ethPayAmtTokens, uint [] memory daiBuyAmtTokens, uint [] memory rateDaiDivEthx10, uint [] memory Ids,
        uint totalBuyAmountDAIToken, uint totalPayAmountEthers, uint totalRateDaiDivEthx10) 
    {

        uint offerId = INVALID_ID;
        ethPayAmtTokens = new uint[](numOrders);
        daiBuyAmtTokens = new uint[](numOrders);    
        rateDaiDivEthx10 = new uint[](numOrders);
        Ids = new uint[](numOrders);
        
        uint offerBuyAmt;
        uint offerPayAmt;
        
        for (uint i = 0; i < numOrders; i++) {
            
            (offerId, offerPayAmt, offerBuyAmt) = getNextBestOffer(DAIToken, wethToken, 1, offerId);
            
            totalBuyAmountDAIToken += offerBuyAmt;
            totalPayAmountEthers += offerPayAmt;
            
            ethPayAmtTokens[i] = offerPayAmt / 10 ** 18;
            daiBuyAmtTokens[i] = offerBuyAmt / 10 ** 18;
            rateDaiDivEthx10[i] = (offerBuyAmt * 10) / offerPayAmt;
            Ids[i] = offerId;
            
            if(offerId == 0) break;
        }
        
        totalRateDaiDivEthx10 = totalBuyAmountDAIToken * 10 / totalPayAmountEthers;
        totalBuyAmountDAIToken /= 10 ** 18;
        totalPayAmountEthers /= 10 ** 18;
    }
    
    function getDaiToEthOrders(uint numOrders) public view
        returns(uint [] memory daiPayAmtTokens, uint [] memory ethBuyAmtTokens, uint [] memory rateDaiDivEthx10, uint [] memory Ids,
        uint totalPayAmountDAIToken, uint totalBuyAmountEthers, uint totalRateDaiDivEthx10)
    {

        uint offerId = INVALID_ID;
        daiPayAmtTokens = new uint[](numOrders);
        ethBuyAmtTokens = new uint[](numOrders);
        rateDaiDivEthx10 = new uint[](numOrders);
        Ids = new uint[](numOrders);
        
        uint offerBuyAmt;
        uint offerPayAmt;

        for (uint i = 0; i < numOrders; i++) {

            (offerId, offerPayAmt, offerBuyAmt) = getNextBestOffer(wethToken, DAIToken, 1, offerId);
            
            totalPayAmountDAIToken += offerPayAmt;
            totalBuyAmountEthers += offerBuyAmt;
            
            daiPayAmtTokens[i] = offerPayAmt / 10 ** 18;
            ethBuyAmtTokens[i] = offerBuyAmt / 10 ** 18;
            rateDaiDivEthx10[i] = (offerPayAmt * 10) / offerBuyAmt;
            Ids[i] = offerId;
            
            if (offerId == 0) break;
        }
        
        totalRateDaiDivEthx10 = totalPayAmountDAIToken * 10 / totalBuyAmountEthers;
        totalPayAmountDAIToken /= 10 ** 18;
        totalBuyAmountEthers /= 10 ** 18;
    }

    function getFirstBidAndAskOrdersPub(ERC20 token)
        public view
        returns(uint bidPayAmt, uint bidBuyAmt, uint askPayAmt, uint askBuyAmt)
    {

        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(token);
        bidPayAmt = bid.payAmount;
        bidBuyAmt = bid.buyAmount;
        askPayAmt = ask.payAmount;
        askBuyAmt = ask.buyAmount;
    }

    function getFirstBidAndAskOrders(ERC20 token) internal view returns(OfferData memory bid, OfferData memory ask) {

        (bid.id, bid.payAmount, bid.buyAmount) = getFirstOffer(token, wethToken);
        (ask.id, ask.payAmount, ask.buyAmount) = getFirstOffer(wethToken, token);
    }

    function checkValidSpreadPub(ERC20 token, uint minSpreadBps) public view returns(bool) {

        OfferData memory bid;
        OfferData memory ask;
        (bid, ask) = getFirstBidAndAskOrders(token);
        return checkValidSpread(bid, ask, true, minSpreadBps);
    }
    
    function checkValidSpread(OfferData memory bid, OfferData memory ask, bool isCheckingMinSpread, uint minSpreadBps)
        internal
        pure
        returns(bool)
    {

        if (bid.id == 0 || ask.id == 0 || bid.buyAmount > MAX_QTY || bid.payAmount > MAX_QTY || ask.buyAmount > MAX_QTY || ask.payAmount > MAX_QTY) {
            return false;
        }


        uint x1 = ask.payAmount * bid.payAmount;
        uint x2 = ask.buyAmount * bid.buyAmount;

        if (x1 <= x2) { return false; }

        if (!isCheckingMinSpread) { return true; }

        if (10000 * (x1 - x2) <= x2 * minSpreadBps) { return false; }

        return true;
    }

    function getTokenBasicDataPub(ERC20 token)
        public view
        returns (uint minETHSupport, uint maxTraverse, uint maxTakes)
    {

        (minETHSupport, maxTraverse, maxTakes) = decodeTokenBasicData(tokenBasicData[address(token)]);
    }

    function getTokenBasicData(ERC20 token) 
        internal view 
        returns(BasicDataConfig memory data)
    {

        (data.minETHSupport, data.maxTraverse, data.maxTakes) = decodeTokenBasicData(tokenBasicData[address(token)]);
    }

    function getFactorDataPub(ERC20 token)
        public view
        returns (uint maxTraverseX, uint maxTraverseY, uint maxTakeX, uint maxTakeY, uint minOrderSizeX, uint minOrderSizeY)
    {

        (maxTraverseX, maxTraverseY, maxTakeX, maxTakeY, minOrderSizeX, minOrderSizeY) = decodeFactorData(tokenFactorData[address(token)]);
    }

    function getFactorData(ERC20 token) 
        internal view 
        returns(FactorDataConfig memory data)
    {

        (data.maxTraverseX, data.maxTraverseY, data.maxTakeX, data.maxTakeY, data.minOrderSizeX, data.minOrderSizeY) = decodeFactorData(tokenFactorData[address(token)]);
    }

    function getInternalInventoryDataPub(ERC20 token)
        public view
        returns(uint minTokenBal, uint maxTokenBal, uint premiumBps, uint minSpreadBps)
    {

        (minTokenBal, maxTokenBal, premiumBps, minSpreadBps) = decodeInternalInventoryData(internalInventoryData[address(token)]);
    }

    function getInternalInventoryData(ERC20 token)
        internal view
        returns(InternalInventoryData memory data)
    {

        (uint minTokenBal, uint maxTokenBal, uint premiumBps, uint minSpreadBps) = decodeInternalInventoryData(internalInventoryData[address(token)]);
        data.minTokenBal = minTokenBal;
        data.maxTokenBal = maxTokenBal;
        data.premiumBps = premiumBps;
        data.minSpreadBps = minSpreadBps;
    }

    function encodeInternalInventoryData(uint minTokenBal, uint maxTokenBal, uint premiumBps, uint minSpreadBps)
        public
        pure
        returns(uint data)
    {

        data = minSpreadBps & (POW_2_32 - 1);
        data |= (premiumBps & (POW_2_32 - 1)) * POW_2_32;
        data |= (maxTokenBal & (POW_2_96 - 1)) * POW_2_32 * POW_2_32;
        data |= (minTokenBal & (POW_2_96 - 1)) * POW_2_96 * POW_2_32 * POW_2_32;
    }

    function decodeInternalInventoryData(uint data)
        public
        pure
        returns(uint minTokenBal, uint maxTokenBal, uint premiumBps, uint minSpreadBps)
    {

        minSpreadBps = data & (POW_2_32 - 1);
        premiumBps = (data / POW_2_32) & (POW_2_32 - 1);
        maxTokenBal = (data / (POW_2_32 * POW_2_32)) & (POW_2_96 - 1);
        minTokenBal = (data / (POW_2_96 * POW_2_32 * POW_2_32)) & (POW_2_96 - 1);
    }

    function encodeTokenBasicData(uint ethSize, uint maxTraverse, uint maxTakes) 
        public
        pure
        returns(uint data)
    {

        data = maxTakes & (POW_2_32 - 1);
        data |= (maxTraverse & (POW_2_32 - 1)) * POW_2_32;
        data |= (ethSize & (POW_2_96 * POW_2_96 - 1)) * POW_2_32 * POW_2_32;
    }

    function decodeTokenBasicData(uint data) 
        public
        pure
        returns(uint ethSize, uint maxTraverse, uint maxTakes)
    {

        maxTakes = data & (POW_2_32 - 1);
        maxTraverse = (data / POW_2_32) & (POW_2_32 - 1);
        ethSize = (data / (POW_2_32 * POW_2_32)) & (POW_2_96 * POW_2_96 - 1);
    }

    function encodeFactorData(uint traverseX, uint traverseY, uint takeX, uint takeY, uint minSizeX, uint minSizeY)
        public
        pure
        returns(uint data)
    {

        data = (minSizeY & (POW_2_32 - 1));
        data |= (minSizeX & (POW_2_32 - 1)) * POW_2_32;
        data |= (takeY & (POW_2_32 - 1)) * POW_2_32 * POW_2_32;
        data |= (takeX & (POW_2_32 - 1)) * POW_2_96;
        data |= (traverseY & (POW_2_32 - 1)) * POW_2_96 * POW_2_32;
        data |= (traverseX & (POW_2_32 - 1)) * POW_2_96 * POW_2_32 * POW_2_32;
    }

    function decodeFactorData(uint data)
        public
        pure
        returns(uint traverseX, uint traverseY, uint takeX, uint takeY, uint minSizeX, uint minSizeY)
    {

        minSizeY = data & (POW_2_32 - 1);
        minSizeX = (data / POW_2_32) & (POW_2_32 - 1);
        takeY = (data / (POW_2_32 * POW_2_32)) & (POW_2_32 - 1);
        takeX = (data / POW_2_96) & (POW_2_32 - 1);
        traverseY = (data / (POW_2_96 * POW_2_32)) & (POW_2_32 - 1);
        traverseX = (data / (POW_2_96 * POW_2_32 * POW_2_32)) & (POW_2_32 - 1);
    }

    function minOf(uint x, uint y) internal pure returns(uint) {

        return x > y ? y : x;
    }

    function calcRateFromQty(uint srcAmount, uint destAmount, uint srcDecimals, uint dstDecimals)
        internal pure returns(uint)
    {

        require(srcAmount <= MAX_QTY, "calcRateFromQty: srcAmount is bigger than MAX_QTY");
        require(destAmount <= MAX_QTY, "calcRateFromQty: destAmount is bigger than MAX_QTY");

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= COMMON_DECIMALS, "calcRateFromQty: dstDecimals - srcDecimals > COMMON_DECIMALS");
            return (destAmount * PRECISION / ((10 ** (dstDecimals - srcDecimals)) * srcAmount));
        } else {
            require((srcDecimals - dstDecimals) <= COMMON_DECIMALS, "calcRateFromQty: srcDecimals - dstDecimals > COMMON_DECIMALS");
            return (destAmount * PRECISION * (10 ** (COMMON_DECIMALS - dstDecimals)) / srcAmount);
        }
    }

    function calcDstQty(uint srcQty, uint srcDecimals, uint dstDecimals, uint rate) internal pure returns(uint) {

        require(srcQty <= MAX_QTY, "calcDstQty: srcQty is bigger than MAX_QTY");
        require(rate <= MAX_RATE, "calcDstQty: rate is bigger than MAX_RATE");

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= COMMON_DECIMALS, "calcDstQty: dstDecimals - srcDecimals > COMMON_DECIMALS");
            return (srcQty * rate * (10**(dstDecimals - srcDecimals))) / PRECISION;
        } else {
            require((srcDecimals - dstDecimals) <= COMMON_DECIMALS, "calcDstQty: srcDecimals - dstDecimals > COMMON_DECIMALS");
            return (srcQty * rate) / (PRECISION * (10**(srcDecimals - dstDecimals)));
        }
    }
    
    function getDecimals(ERC20 token) internal view returns(uint) {

        if (token == ETH_TOKEN_ADDRESS) { return COMMON_DECIMALS; }
        return token.decimals();
    }
}