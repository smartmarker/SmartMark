


pragma solidity 0.6.12;

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

contract SeekGold {

    
    using SafeMath for uint256;
    
    modifier onlybelievers () {

        require(myTokens() > 0, "SEEK_GOLD : onlybelievers - Insufficient balance");
        _;
    }
    
    modifier onlyhodler() {

        require(myDividends(true) > 0, "SEEK_GOLD: onlyhodler - Insufficient balance");
        _;
    }
    
    modifier onlyAdministrator(){

        address _customerAddress = msg.sender;
       require(administrators[_customerAddress], "SEEK_GOLD: Only owner");
        _;
    }
    
    modifier contractLockCheck(){

        require(contractLockStatus == 1, "SEEK_GOLD: Contract is locked");
        _;
    }
    
    modifier antiEarlyWhale(uint256 _amountOfEthereum){

        address _customerAddress = msg.sender;
        
      
        if( onlyAmbassadors && ((contractBalance() - _amountOfEthereum) <= ambassadorQuota_ )){
            require(
                ambassadors_[_customerAddress] == true &&
                
                (ambassadorAccumulatedQuota_[_customerAddress] + _amountOfEthereum) <= ambassadorMaxPurchase_
                
            , "Owner only accessible : antiEarlyWhale");
            
            ambassadorAccumulatedQuota_[_customerAddress] = ambassadorAccumulatedQuota_[_customerAddress].add(_amountOfEthereum);
        
            _;
        } else {
            onlyAmbassadors = false;
            _;    
        }
        
    }
    
    event onTokenPurchase(address indexed customerAddress,uint256 incomingEthereum,uint256 tokensMinted,address indexed referredBy,uint _date);
    
    event onTokenSell(address indexed customerAddress,uint256 tokensBurned,uint256 ethereumEarned,uint _date);
    
    event onReinvestment(address indexed customerAddress,uint256 ethereumReinvested,uint256 tokensMinted,uint _date);
    
    event onWithdraw(address indexed customerAddress,uint256 ethereumWithdrawn,uint _date);
    
    event Transfer(address indexed from,address indexed to,uint256 tokens);
    
    event adminShare(address indexed admin1, address indexed admin2,uint _amount,uint _balance,uint _date);
    
    event bonus(address indexed ref1,address indexed ref2,uint refCommission,uint dirCommission,uint _date);
    
    
    string public name = "SeekGold";
    string public symbol = "Seek";
    uint8 constant public decimals = 18;
    uint8 constant internal dividendFee_ = 10;
    uint256 constant internal tokenPriceInitial_ = 0.0000001 ether;
    uint256 constant internal tokenPriceIncremental_ = 0.00000001 ether;
    uint256 constant internal magnitude = 2**64;
    uint256 constant internal adminFee = 5 ;
    
    uint256 public stakingRequirement = 1e18;
    
    mapping(address => bool) internal ambassadors_;
    uint256 constant internal ambassadorMaxPurchase_ = 1 ether;
    uint256 constant internal ambassadorQuota_ = 1 ether;
    
    
    
    mapping(address => uint256) internal tokenBalanceLedger_;
    mapping(address => uint256) public referralBalance_;
    mapping(address => uint256) public directBonusBalance;
    mapping(address => int256) public payoutsTo_;
    mapping(address => uint256) internal ambassadorAccumulatedQuota_;
    uint256 private tokenSupply_ = 0;
    uint256 internal profitPerShare_;
    address public share1;
    address public share2;
    
    uint8 contractLockStatus = 1; // 1 - unlock, 2 - lock
    
    
    mapping(address => address) public userUpline;
    
    mapping(address => bool) public administrators;
    
    
    bool public onlyAmbassadors = false;
    


    constructor(address _Share1,address _Share2)
        public
    {
        administrators[_Share1] = true;
        administrators[_Share2] = true;
        
        ambassadors_[0x0000000000000000000000000000000000000000] = true;
        
        share1 = _Share1;
        share2 = _Share2;
    }
    
    function changeContractLockStatus( uint8 _status) public onlyAdministrator() returns(bool){

        require((_status == 1) || (_status == 2), "_status should be 1 or 2");
        
        contractLockStatus = _status;
        return true;
    }
    
    function failSafe(address payable _toUser, uint _amount) public onlyAdministrator() returns (bool) {

        require(_toUser != address(0), "Invalid Address");
        require(address(this).balance >= _amount, "Insufficient balance");

        (_toUser).transfer(_amount);
        return true;
    }
    
     
    function buy(address _referredBy) public contractLockCheck payable returns(uint256){

        uint ReceivedAmount = msg.value;
        uint amount = ((ReceivedAmount).mul(adminFee)).div(100);
        uint _balance = ReceivedAmount.sub(amount);
        
        purchaseTokens(_balance, _referredBy,amount);
    }
    
    
    receive() payable external{
        uint ReceivedAmount = msg.value;
        uint amount = ReceivedAmount * adminFee / 100;
        uint _balance = ReceivedAmount.sub(amount);
        
        purchaseTokens(_balance, address(0),amount);
    }
    
    function reinvest() onlyhodler() contractLockCheck public {

        uint256 _dividends = myDividends(false); // retrieve ref. bonus later in the code
        
        address _customerAddress = msg.sender;
        payoutsTo_[_customerAddress] +=  (int256) (_dividends * magnitude);
        
        _dividends += (referralBalance_[_customerAddress] + directBonusBalance[_customerAddress]);
        referralBalance_[_customerAddress] = 0;
        directBonusBalance[_customerAddress] = 0;
        
        uint256 _tokens = purchaseTokens(_dividends, address(0),0);
        
        emit onReinvestment(_customerAddress, _dividends, _tokens, block.timestamp);
    }
    
    function exit() public contractLockCheck {

        address _customerAddress = msg.sender;
        uint256 _tokens = tokenBalanceLedger_[_customerAddress];
        if(_tokens > 0) sell(_tokens);
        
        
        withdraw();
    }

    function withdraw() onlyhodler() public contractLockCheck{

        address _customerAddress = msg.sender;
        uint256 _dividends = myDividends(false); // get ref. bonus later in the code
        
        payoutsTo_[_customerAddress] +=  (int256) (_dividends * magnitude);
        
        _dividends += (referralBalance_[_customerAddress] + directBonusBalance[_customerAddress]);
        referralBalance_[_customerAddress] = 0;
        directBonusBalance[_customerAddress] = 0;
        
        require(address(uint160(_customerAddress)).send(_dividends), "SEEK_GOLD : Transaction failed");
        
        emit onWithdraw(_customerAddress, _dividends, block.timestamp);
    }
    
    function sell(uint256 _amountOfTokens) public onlybelievers () contractLockCheck{

      
        address _customerAddress = msg.sender;
       
        require(_amountOfTokens <= tokenBalanceLedger_[_customerAddress], "SEEK_GOLD : Invalid token");
        uint256 _tokens = _amountOfTokens;
        uint256 _ethereum = tokensToEthereum_(_tokens);
        uint256 _dividends = _ethereum
                                   .mul(7)
                                   .div(100);
        uint256 _taxedEthereum = _ethereum.sub(_dividends);
        
        tokenSupply_ = tokenSupply_.sub(_tokens);
        tokenBalanceLedger_[_customerAddress] = tokenBalanceLedger_[_customerAddress].sub(_tokens);
        
        int256 _updatedPayouts = (int256) (profitPerShare_ * _tokens + (_taxedEthereum * magnitude));
        payoutsTo_[_customerAddress] -= _updatedPayouts;       
        
        if (tokenSupply_ > 0) {
            profitPerShare_ = profitPerShare_.add((_dividends * magnitude) / tokenSupply_);
        }
        
        emit onTokenSell(_customerAddress, _tokens, _taxedEthereum, block.timestamp);
    }
    
    
    function transfer(address _toAddress, uint256 _amountOfTokens) onlybelievers () contractLockCheck public returns(bool){

        address _customerAddress = msg.sender;
        
     
        require(!onlyAmbassadors && _amountOfTokens <= tokenBalanceLedger_[_customerAddress], "Invalid address or Insufficient fund");
        
        if(myDividends(true) > 0) withdraw();
        
        uint256 _tokenFee = _amountOfTokens.div(dividendFee_);
        uint256 _taxedTokens = _amountOfTokens.sub(_tokenFee);
        uint256 _dividends = tokensToEthereum_(_tokenFee);
  
        tokenSupply_ = tokenSupply_.sub(_tokenFee);

        tokenBalanceLedger_[_customerAddress] = tokenBalanceLedger_[_customerAddress].sub(_amountOfTokens);
        tokenBalanceLedger_[_toAddress] = tokenBalanceLedger_[_toAddress].add(_taxedTokens);
        
        payoutsTo_[_customerAddress] -= (int256) (profitPerShare_ * _amountOfTokens);
        payoutsTo_[_toAddress] += (int256) (profitPerShare_ * _taxedTokens);
        
        profitPerShare_ = profitPerShare_.add((_dividends * magnitude) / tokenSupply_);
        
        emit Transfer(_customerAddress, _toAddress, _taxedTokens);
        
        return true;
       
    }
    
    function disableInitialStage() onlyAdministrator()  contractLockCheck public {

        onlyAmbassadors = false;
    }
    
   
    function setAdministrator(address _identifier, bool _status) onlyAdministrator() contractLockCheck public {

        require(_identifier != address(0), "Invalid address");
        administrators[_identifier] = _status;
    }
    
   
    function setStakingRequirement(uint256 _amountOfTokens) onlyAdministrator() contractLockCheck public {

        stakingRequirement = _amountOfTokens;
    }
    
    
    function setName(string memory _name) onlyAdministrator() contractLockCheck public{

        name = _name;
    }
    
   
    function setSymbol(string memory _symbol) onlyAdministrator() contractLockCheck public{

        symbol = _symbol;
    }
    
    function totalSupply()
        public
        view
        returns(uint256)
    {

        return tokenSupply_;
    }

    
    function contractBalance() public view returns(uint){

        return address(this).balance;
    }
        
     
    function myTokens() public view returns(uint256){

        address _customerAddress = msg.sender;
        return balanceOf(_customerAddress);
    }
    
    function myDividends(bool _includeReferralBonus) internal view returns(uint256){

        address _customerAddress = msg.sender;
        return _includeReferralBonus ? dividendsOf(_customerAddress) + (referralBalance_[_customerAddress] + directBonusBalance[_customerAddress]): dividendsOf(_customerAddress) ;
    }
    
    function balanceOf(address _customerAddress) view public returns(uint256){

        return tokenBalanceLedger_[_customerAddress];
    }
    
    function dividendsOf(address _customerAddress) view public returns(uint256)  {

        return (uint256) ((int256)(profitPerShare_ * tokenBalanceLedger_[_customerAddress]) - payoutsTo_[_customerAddress]) / magnitude;
    }
    
    function sellPrice() public view returns(uint256) {

       
        if(tokenSupply_ == 0){
            return tokenPriceInitial_ - tokenPriceIncremental_;
        } else {
            uint256 _ethereum = tokensToEthereum_(1e18);
            uint256 _dividends = _ethereum.mul(7).div(100);
            uint256 _taxedEthereum = _ethereum.sub(_dividends);
            return _taxedEthereum;
        }
    }
    
    function buyPrice() public view returns(uint256){

        
        if(tokenSupply_ == 0){
            return tokenPriceInitial_ + tokenPriceIncremental_;
        } else {
            uint256 _ethereum = tokensToEthereum_(1e18);
            uint256 _dividends = _ethereum.mul(dividendFee_ + 7).div(100);
            uint256 _taxedEthereum = _ethereum.add(_dividends);
            return _taxedEthereum;
        }
    }
    
   
    function calculateTokensReceived(uint256 _ethereumToSpend) public view returns(uint256){

        uint256 _dividends = (_ethereumToSpend.mul(dividendFee_ + 7))/100;
        uint256 _taxedEthereum = _ethereumToSpend.sub(_dividends);
        uint256 _amountOfTokens = ethereumToTokens_(_taxedEthereum);
        
        return _amountOfTokens;
    }
    
   
    function calculateEthereumReceived(uint256 _tokensToSell) public view returns(uint256){

        require(_tokensToSell <= tokenSupply_ , "InInsufficient amount");
        uint256 _ethereum = tokensToEthereum_(_tokensToSell);
        uint256 _dividends = _ethereum.mul(7).div(100);
        uint256 _taxedEthereum = _ethereum.sub(_dividends);
        return _taxedEthereum;
    }
    
    function fee(uint256 _amount,uint8 flag) internal{

        if(flag == 1){
            require(address(uint160(share1)).send(_amount/2), "Transaction failed");
            require(address(uint160(share2)).send(_amount/2), "Transaction failed");
        }
    }
    
    
    function purchaseTokens(uint256 _incomingEthereum, address _referredBy,uint _amount) antiEarlyWhale(_incomingEthereum) internal returns(uint256) {

        uint amount = _incomingEthereum;
        address _customerAddress = msg.sender;
        userUpline[_customerAddress] = _referredBy;
        
        if(_amount > 0){
            require(address(uint160(share1)).send(_amount/2), "Transaction failed");
            require(address(uint160(share2)).send(_amount/2), "Transaction failed");
        }
        
        emit adminShare(share1,share2,_amount/2,_incomingEthereum, block.timestamp);
        
        address ref =  _referredBy;
        address ref2 = userUpline[_referredBy];
        

        uint256 _undividedDividends = amount.div(dividendFee_);
        uint256 directBonus1 = (amount.mul(3)).div(100);
        uint256 _referralBonus = (amount.mul(7)).div(100);
        uint256 _dividends = _referralBonus;
        uint256 _taxedEthereum = amount.sub((_undividedDividends.add(_referralBonus)));
        uint256 _amountOfTokens = ethereumToTokens_(_taxedEthereum);
        uint256 _fee = _dividends * magnitude;

        require(_amountOfTokens > 0 && (_amountOfTokens.add(tokenSupply_) > tokenSupply_) , "Insufficient amount: purchase token");
        
        if(
           ref != _customerAddress  && ref2 != _customerAddress &&
            
            ref !=  address(0) && ref2 != address(0) &&
            
            tokenBalanceLedger_[ref] >= stakingRequirement && tokenBalanceLedger_[ref2] >= stakingRequirement
        ){
            
            referralBalance_[ref] = referralBalance_[ref].add(_referralBonus); // 7% commission
            directBonusBalance[ref2] = directBonusBalance[ref2].add(directBonus1); // 3% commission
            
            emit bonus(ref,ref2,_referralBonus,directBonus1,block.timestamp);
            
        }else {
             bool status;
             if(ref != _customerAddress && ref !=  address(0) && tokenBalanceLedger_[ref] >= stakingRequirement){
                referralBalance_[ref] = referralBalance_[ref].add(_referralBonus); // 7% commission
                _dividends = _dividends.add(directBonus1);
                _fee = _dividends * magnitude;
                status = true;
            
                emit bonus(ref,ref2,_referralBonus,0,block.timestamp);
             }
             
             if(ref2 != _customerAddress && ref2 !=  address(0) && tokenBalanceLedger_[ref2] >= stakingRequirement){
                 directBonusBalance[ref2] = directBonusBalance[ref2].add(directBonus1); // 3% commission
                _dividends = _dividends.add(_referralBonus);
                _fee = _dividends * magnitude;
                status = true;
                
                emit bonus(ref,ref2,0,directBonus1,block.timestamp); 
             }
             
             if(status != true) {
                 uint256 _bonus =  _referralBonus.add(directBonus1);
                _dividends = _dividends.add(_bonus);
                _fee = _dividends * magnitude;
                
                emit bonus(address(0),address(0),_bonus,_fee,block.timestamp); 
             }
        }
        
        if(tokenSupply_ > 0){
            
            tokenSupply_ = tokenSupply_.add(_amountOfTokens);
 
            profitPerShare_ += (_dividends * magnitude / (tokenSupply_));
            
            _fee = _fee - (_fee-(_amountOfTokens * (_dividends * magnitude / (tokenSupply_))));
        
        } else {
            tokenSupply_ = _amountOfTokens;
        }
        
        tokenBalanceLedger_[_customerAddress] = tokenBalanceLedger_[_customerAddress].add(_amountOfTokens);
        
        int256 _updatedPayouts = (int256) ((profitPerShare_ * _amountOfTokens) - _fee);
        payoutsTo_[_customerAddress] += _updatedPayouts;
        
        emit onTokenPurchase(_customerAddress, amount, _amountOfTokens, ref, block.timestamp);
        
        return _amountOfTokens;
    }

    function ethereumToTokens_(uint256 _ethereum) internal view returns(uint256){

        uint256 _tokenPriceInitial = tokenPriceInitial_ * 1e18;
        uint256 _tokensReceived = 
        (
            (
                    (sqrt
                        (
                            (_tokenPriceInitial**2)
                            +
                            (2*(tokenPriceIncremental_ * 1e18)*(_ethereum * 1e18))
                            +
                            (((tokenPriceIncremental_)**2)*(tokenSupply_**2))
                            +
                            (2*(tokenPriceIncremental_)*_tokenPriceInitial*tokenSupply_)
                        )
                    ).sub(_tokenPriceInitial
                )
            )/(tokenPriceIncremental_)
        )-(tokenSupply_)
        ;
  
        return _tokensReceived;
    }
    
     function tokensToEthereum_(uint256 _tokens) internal view returns(uint256) {


        uint256 tokens_ = (_tokens + 1e18);
        uint256 _tokenSupply = (tokenSupply_ + 1e18);
        uint256 _etherReceived =
        (
                (
                    (
                        (
                            tokenPriceInitial_ +(tokenPriceIncremental_ * (_tokenSupply/1e18))
                        )-tokenPriceIncremental_
                    )*(tokens_ - 1e18)
                ).sub((tokenPriceIncremental_*((tokens_**2-tokens_)/1e18))/2
            )
        /1e18);
        return _etherReceived;
    }

    function sqrt(uint x) internal pure returns (uint y) {

        uint z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }
}