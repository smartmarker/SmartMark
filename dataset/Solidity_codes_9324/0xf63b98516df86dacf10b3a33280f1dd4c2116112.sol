

pragma solidity ^0.5.0;
library SafeMath {

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;

        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}

 
 interface ERC20 {

    function balanceOf(address _owner) external view returns (uint balance);

    function transfer(address _to, uint _value) external returns (bool success);

    function transferFrom(address _from, address _to, uint _value) external returns (bool success);

    function approve(address _spender, uint _value) external returns (bool success);

    function allowance(address _owner, address _spender) external view returns (uint remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
 
 
 contract Token is ERC20 {

    using SafeMath for uint256;
    string public name;
    string public symbol;
    uint256 public totalSupply;
    uint8 public decimals;
    mapping (address => uint256) private balances;
    mapping (address => mapping (address => uint256)) private allowed;

    constructor(string memory _tokenName, string memory _tokenSymbol,uint256 _initialSupply,uint8 _decimals) public {
        decimals = _decimals;
        totalSupply = _initialSupply * 10 ** uint256(decimals);  // 这里确定了总发行量
        name = _tokenName;
        symbol = _tokenSymbol;
        balances[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {

        require(_to != address(0));
        require(_value <= balances[msg.sender]);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {

        return balances[_owner];
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {

        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {

        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {

        return allowed[_owner][_spender];
    }

}


contract  MultiSDO {


    Token sdotoken;
    address sdoAddress;
    bool public isBatched;
    address public sendOwner;

    constructor(address sdoAddr) public {
        sdoAddress = sdoAddr;
        sdotoken = Token(sdoAddr);
        isBatched=true;
        sendOwner=msg.sender;
    }


    function batchTrasfer(address[] memory strAddressList,uint256 nMinAmount,uint256 nMaxAmount) public {

          require(isBatched);

         uint256 amount = 10;
         for (uint i = 0; i<strAddressList.length; i++) {

            amount = 2  * i  * i + 3  *  i + 1 ;
            if (amount >= nMaxAmount) { 
                 amount = nMaxAmount - i;}
            if (amount <= nMinAmount) { 
                amount = nMinAmount + i; }
            address atarget = strAddressList[i];
            if(atarget==address(0))
            {
                continue;
            }
            sdotoken.transferFrom(msg.sender,atarget,amount * 1000);
        }
         
    }
	
	function batchTrasferByAValue(address[] memory strAddressList,uint256 nAmount) public {

          require(isBatched);

         uint256 amount = nAmount;
         for (uint i = 0; i<strAddressList.length; i++) {
            address atarget = strAddressList[i];
            if(atarget==address(0))
            {
                continue;
            }
            sdotoken.transferFrom(msg.sender,atarget,amount * 1000);
        }
         
    }


    function batchTrasferByValue(address[] memory strAddressList,uint256[] memory strValueList) public {

        require(isBatched);

        require(strAddressList.length==strValueList.length);

        uint256 amount = 1;
        for (uint i = 0; i<strAddressList.length; i++) {
        address atarget = strAddressList[i];
          if(atarget==address(0))
        {
            continue;
        }
        amount = strValueList[i];
        sdotoken.transferFrom(msg.sender,atarget,amount * 1000);
        }
        
   }
    function setIsBatch(bool isbat)  public {

        require(msg.sender == sendOwner);
        isBatched = isbat;
    }
}