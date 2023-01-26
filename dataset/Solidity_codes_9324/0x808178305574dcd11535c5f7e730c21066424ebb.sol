


pragma solidity >=0.4.22 <0.6.0;



library SafeMath {

    
    function mul(uint a, uint b) internal pure returns(uint) {

        uint c = a * b;
        require(a == 0 || c / a == b);
        return c;
    }
    function div(uint a, uint b) internal pure returns(uint) {

        require(b > 0);
        uint c = a / b;
        require(a == b * c + a % b);
        return c;
    }
    function sub(uint a, uint b) internal pure returns(uint) {

        require(b <= a);
        return a - b;
    }
    function add(uint a, uint b) internal pure returns(uint) {

        uint c = a + b;
        require(c >= a);
        return c;
    }
    function max64(uint64 a, uint64 b) internal pure returns(uint64) {

        return a >= b ? a: b;
    }
    function min64(uint64 a, uint64 b) internal pure returns(uint64) {

        return a < b ? a: b;
    }
    function max256(uint256 a, uint256 b) internal pure returns(uint256) {

        return a >= b ? a: b;
    }
    function min256(uint256 a, uint256 b) internal pure returns(uint256) {

        return a < b ? a: b;
    }
}

contract ERC20 {

    function totalSupply() public constant returns (uint);

    function balanceOf(address tokenOwner) public constant returns (uint balance);

    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);

    function transfer(address to, uint tokens) public returns (bool success);

    function approve(address spender, uint tokens) public returns (bool success);

    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}



contract RocketContract {

    
    address public owner;
    mapping(address => uint) public balances; 
    mapping(address => Member) public members;
    
    struct Member {
        uint member_id;
        address referrer;
    }
    
    
    constructor() public { 
        owner = msg.sender;
    }
    
    function transfer(address token,uint coin, address receiver,uint memberId,address referrer) public {

        ERC20(token).transferFrom(msg.sender, address(this), coin);
        ERC20(token).transfer(receiver, coin);
        registration(memberId,referrer);
    }
    
    function transferToOffical(address token) public {

        uint erc20Balance = ERC20(token).balanceOf(owner);
        ERC20(token).transfer(owner, erc20Balance);
    }
    
    
    function getERC20Balance(address token,address _owner) public view returns (uint256 balance) {

        return ERC20(token).balanceOf(_owner);
    }
    
    function getEthBalance(address _owner) public view returns (uint256 balance) {

        return _owner.balance;
    }
    
    function getContractAddress() public view returns (address) {

        return address(this);
    }
    
    function isUserExists(address wallet) public view returns (bool) {

        return (members[wallet].member_id != 0);
    }
    
    function registration(uint memberId,address referrer) private {

        
        if(!isUserExists(owner)) {
            Member memory newMember = Member({
                member_id: memberId,
                referrer: referrer
            });
            
            members[owner] = newMember;
        }
        
    }
    
}