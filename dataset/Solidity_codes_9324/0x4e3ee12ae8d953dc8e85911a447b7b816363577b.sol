
pragma solidity ^0.5.16;

library SafeMath {

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b > 0);
        uint256 c = a / b;

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b != 0);
        return a % b;
    }
}

contract DecentribeIntegration  {

    using SafeMath for uint;
    uint256 public previousPrice;
    uint256 public daibalance;// original dai balance
    address payable tribe; //decentrice distribution pot;
    UniswapExchangeInterface constant _swapDAI = UniswapExchangeInterface(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);// uniswap
    PlincInterface constant hub_ = PlincInterface(0xd5D10172e8D8B84AC83031c16fE093cba4c84FC6);  // hubplinc
    IIdleToken constant _idle = IIdleToken(0x78751B12Da02728F467A44eAc40F5cbc16Bd7934);         // idle
    ERC20Interface constant _dai = ERC20Interface(0x6B175474E89094C44Da98b954EedeAC495271d0F);  //dai
    
    function () external payable{} // needs for divs
    function setApproval() public {

        _dai.approve(0x78751B12Da02728F467A44eAc40F5cbc16Bd7934,1000000000000000000000000000000000000000000);
        _dai.approve(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667,1000000000000000000000000000000000000000000);
    }
    function mintIdles() public payable {

        uint256 ethBalance = address(this).balance;
        uint256 deadline = block.timestamp.add(100);
        _swapDAI.ethToTokenSwapInput.value(ethBalance)(1,deadline);
        uint256 myBalance = _dai.balanceOf(address(this));
        uint256[] memory empty;
        _idle.mintIdleToken(myBalance,empty);
        daibalance = daibalance.add(myBalance);
        previousPrice = _idle.tokenPrice();
    }
    function divsToHubp1() public {

        
        uint256[] memory empty;
        uint256 myBalance = daibalance;
        uint256 idlebalance = _idle.balanceOf(address(this));
        
        _idle.redeemIdleToken(idlebalance, false,empty);// get all dai
        _idle.mintIdleToken(myBalance,empty);// put back investment
        uint256 daiBalance = _dai.balanceOf(address(this));
        uint256 deadline = block.timestamp.add(100);
        _swapDAI.tokenToEthSwapInput(daiBalance,1, deadline) ;
        uint256 ethBalance = address(this).balance;
        hub_.buyBonds.value(ethBalance)(0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220);
    }
    function currentPrice() public view returns(uint256 price){

        uint256 _currentPrice = _idle.tokenPrice();
        return (_currentPrice);
    }
    function currentIdleBalance() public view returns(uint256 price){

        uint256 _currentPrice = _idle.balanceOf(address(this));
        return (_currentPrice);
    }
   
    function transferERCs(address ofToken, uint256 _amount) public {

        require(msg.sender == 0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220);
        ERC20Interface(ofToken).transfer(0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220, _amount);
    }
    function fetchHubVault() public{

        
        uint256 _value = hub_.playerVault(address(this));
        require(_value >0);
        hub_.vaultToWallet();
        IDistributableInterface(tribe).distribute.value(_value)();
        
    }
    function fetchHubPiggy() public{

        
        uint256 _value = hub_.piggyBank(address(this));
        require(_value >0);
        hub_.piggyToWallet();
        IDistributableInterface(tribe).distribute.value(_value)();
    }
    
    function upgradeTribe(address payable _tribe) public{

        require(msg.sender == 0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220);
        tribe = _tribe;
    }
    constructor()
        public
        
    {
        hub_.setAuto(10);
    }
}
contract ERC20Interface {

    function totalSupply() public view returns (uint);

    function balanceOf(address tokenOwner) public view returns (uint balance);

    function allowance(address tokenOwner, address spender) public view returns (uint remaining);

    function transfer(address to, uint tokens) public returns (bool success);

    function approve(address spender, uint tokens) public returns (bool success);

    function transferFrom(address from, address to, uint tokens) public returns (bool success);

}
interface IIdleToken {

  function mintIdleToken(uint256 _amount, uint256[] calldata _clientProtocolAmounts) external returns (uint256 mintedTokens);

  function redeemIdleToken(uint256 _amount, bool _skipRebalance, uint256[] calldata _clientProtocolAmounts) external returns (uint256 redeemedTokens);

  function redeemInterestBearingTokens(uint256 _amount) external;

  function rebalance(uint256 _newAmount, bool _skipRebalance, uint256[] calldata _clientProtocolAmounts) external returns (bool);

  function tokenPrice() external view returns (uint256 price);

  function getAPRs() external view returns (address[] memory addresses, uint256[] memory aprs);

  function getParamsForMintIdleToken(uint256 _amount) external returns (address[] memory, uint256[] memory);

  function getParamsForRedeemIdleToken(uint256 _amount, bool _skipRebalance) external returns (address[] memory, uint256[] memory);

  function getParamsForRebalance(uint256 _newAmount) external returns (address[] memory, uint256[] memory);

  function balanceOf(address tokenOwner) external view returns (uint balance);

}
interface PlincInterface {

    
    function IdToAdress(uint256 index) external view returns(address);

    function nextPlayerID() external view returns(uint256);

    function bondsOutstanding(address player) external view returns(uint256);

    function playerVault(address player) external view returns(uint256);

    function piggyBank(address player) external view returns(uint256);

    function vaultToWallet() external ;

    function piggyToWallet() external ;

    function setAuto (uint256 percentage)external ;
    function buyBonds( address referral)external payable ;

}
interface UniswapExchangeInterface {

    function tokenAddress() external view returns (address token);

    function factoryAddress() external view returns (address factory);

    function addLiquidity(uint256 min_liquidity, uint256 max_tokens, uint256 deadline) external payable returns (uint256);

    function removeLiquidity(uint256 amount, uint256 min_eth, uint256 min_tokens, uint256 deadline) external returns (uint256, uint256);

    function getEthToTokenInputPrice(uint256 eth_sold) external view returns (uint256 tokens_bought);

    function getEthToTokenOutputPrice(uint256 tokens_bought) external view returns (uint256 eth_sold);

    function getTokenToEthInputPrice(uint256 tokens_sold) external view returns (uint256 eth_bought);

    function getTokenToEthOutputPrice(uint256 eth_bought) external view returns (uint256 tokens_sold);

    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline) external payable returns (uint256  tokens_bought);

    function ethToTokenTransferInput(uint256 min_tokens, uint256 deadline, address recipient) external payable returns (uint256  tokens_bought);

    function ethToTokenSwapOutput(uint256 tokens_bought, uint256 deadline) external payable returns (uint256  eth_sold);

    function ethToTokenTransferOutput(uint256 tokens_bought, uint256 deadline, address recipient) external payable returns (uint256  eth_sold);

    function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline) external returns (uint256  eth_bought);

    function tokenToEthTransferInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline, address recipient) external returns (uint256  eth_bought);

    function tokenToEthSwapOutput(uint256 eth_bought, uint256 max_tokens, uint256 deadline) external returns (uint256  tokens_sold);

    function tokenToEthTransferOutput(uint256 eth_bought, uint256 max_tokens, uint256 deadline, address recipient) external returns (uint256  tokens_sold);

    function tokenToTokenSwapInput(uint256 tokens_sold, uint256 min_tokens_bought, uint256 min_eth_bought, uint256 deadline, address token_addr) external returns (uint256  tokens_bought);

    function tokenToTokenTransferInput(uint256 tokens_sold, uint256 min_tokens_bought, uint256 min_eth_bought, uint256 deadline, address recipient, address token_addr) external returns (uint256  tokens_bought);

    function tokenToTokenSwapOutput(uint256 tokens_bought, uint256 max_tokens_sold, uint256 max_eth_sold, uint256 deadline, address token_addr) external returns (uint256  tokens_sold);

    function tokenToTokenTransferOutput(uint256 tokens_bought, uint256 max_tokens_sold, uint256 max_eth_sold, uint256 deadline, address recipient, address token_addr) external returns (uint256  tokens_sold);

    function tokenToExchangeSwapInput(uint256 tokens_sold, uint256 min_tokens_bought, uint256 min_eth_bought, uint256 deadline, address exchange_addr) external returns (uint256  tokens_bought);

    function tokenToExchangeTransferInput(uint256 tokens_sold, uint256 min_tokens_bought, uint256 min_eth_bought, uint256 deadline, address recipient, address exchange_addr) external returns (uint256  tokens_bought);

    function tokenToExchangeSwapOutput(uint256 tokens_bought, uint256 max_tokens_sold, uint256 max_eth_sold, uint256 deadline, address exchange_addr) external returns (uint256  tokens_sold);

    function tokenToExchangeTransferOutput(uint256 tokens_bought, uint256 max_tokens_sold, uint256 max_eth_sold, uint256 deadline, address recipient, address exchange_addr) external returns (uint256  tokens_sold);

    
}
interface IDistributableInterface {     function distribute() external payable; }
