
pragma solidity 0.7.5;

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

    function sqrrt(uint256 a) internal pure returns (uint c) {

        if (a > 3) {
            c = a;
            uint b = add( div( a, 2), 1 );
            while (b < c) {
                c = b;
                b = div( add( div( a, b ), b), 2 );
            }
        } else if (a != 0) {
            c = 1;
        }
    }

    function percentageAmount( uint256 total_, uint8 percentage_ ) internal pure returns ( uint256 percentAmount_ ) {

        return div( mul( total_, percentage_ ), 1000 );
    }

    function substractPercentage( uint256 total_, uint8 percentageToSub_ ) internal pure returns ( uint256 result_ ) {

        return sub( total_, div( mul( total_, percentageToSub_ ), 1000 ) );
    }

    function percentageOfTotal( uint256 part_, uint256 total_ ) internal pure returns ( uint256 percent_ ) {

        return div( mul(part_, 100) , total_ );
    }

    function average(uint256 a, uint256 b) internal pure returns (uint256) {

        return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);
    }

    function quadraticPricing( uint256 payment_, uint256 multiplier_ ) internal pure returns (uint256) {

        return sqrrt( mul( multiplier_, payment_ ) );
    }

  function bondingCurve( uint256 supply_, uint256 multiplier_ ) internal pure returns (uint256) {

      return mul( multiplier_, supply_ );
  }
}

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

contract OHMCirculatingSupplyContract {

    using SafeMath for uint;

    bool public isInitialized;

    address public OHM;
    address public owner;
    address[] public nonCirculatingOHMAddresses;


    constructor( address _owner ) {        
        owner = _owner;
    }

    function initialize( address _ohm ) external returns ( bool ) {

        require( msg.sender == owner, "caller is not owner" );
        require( isInitialized == false );

        OHM = _ohm;

        isInitialized = true;

        return true;
    }

    function OHMCirculatingSupply() external view returns ( uint ) {

        uint _totalSupply = IERC20( OHM ).totalSupply();

        uint _circulatingSupply = _totalSupply.sub( getNonCirculatingOHM() );

        return _circulatingSupply;
    }

    function getNonCirculatingOHM() public view returns ( uint ) {

        uint _nonCirculatingOHM;

        for( uint i=0; i < nonCirculatingOHMAddresses.length; i = i.add( 1 ) ) {
            _nonCirculatingOHM = _nonCirculatingOHM.add( IERC20( OHM ).balanceOf( nonCirculatingOHMAddresses[i] ) );
        }

        return _nonCirculatingOHM;
    }

    function setNonCirculatingOHMAddresses( address[] calldata _nonCirculatingAddresses ) external returns ( bool ) {

        require( msg.sender == owner, "Sender is not owner" );
        nonCirculatingOHMAddresses = _nonCirculatingAddresses;

        return true;
    }

    function transferOwnership( address _owner ) external returns ( bool ) {

        require( msg.sender == owner, "Sender is not owner" );

        owner = _owner;

        return true;
    }
}