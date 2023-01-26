
pragma solidity 0.5.7;

library SafeMath {


  function mul(uint256 _a, uint256 _b) internal pure returns (uint256) {

    if (_a == 0) {
      return 0;
    }

    uint256 c = _a * _b;
    require(c / _a == _b);

    return c;
  }

  function div(uint256 _a, uint256 _b) internal pure returns (uint256) {

    require(_b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = _a / _b;

    return c;
  }

  function sub(uint256 _a, uint256 _b) internal pure returns (uint256) {

    require(_b <= _a);
    uint256 c = _a - _b;

    return c;
  }

  function add(uint256 _a, uint256 _b) internal pure returns (uint256) {

    uint256 c = _a + _b;
    require(c >= _a);

    return c;
  }

  function mod(uint256 a, uint256 b) internal pure returns (uint256) {

    require(b != 0);
    return a % b;
  }
}

contract ERC20 {

  function totalSupply() public view returns (uint256);


  function balanceOf(address _who) public view returns (uint256);


  function allowance(address _owner, address _spender)
    public view returns (uint256);


  function transfer(address _to, uint256 _value) public returns (bool);


  function approve(address _spender, uint256 _value)
    public returns (bool);


  function transferFrom(address _from, address _to, uint256 _value)
    public returns (bool);


  function decimals() public view returns (uint256);


  event Transfer(
    address indexed from,
    address indexed to,
    uint256 value
  );

  event Approval(
    address indexed owner,
    address indexed spender,
    uint256 value
  );
}

library ERC20SafeTransfer {

    function safeTransfer(address _tokenAddress, address _to, uint256 _value) internal returns (bool success) {

        (success,) = _tokenAddress.call(abi.encodeWithSignature("transfer(address,uint256)", _to, _value));
        require(success, "Transfer failed");

        return fetchReturnData();
    }

    function safeTransferFrom(address _tokenAddress, address _from, address _to, uint256 _value) internal returns (bool success) {

        (success,) = _tokenAddress.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", _from, _to, _value));
        require(success, "Transfer From failed");

        return fetchReturnData();
    }

    function safeApprove(address _tokenAddress, address _spender, uint256 _value) internal returns (bool success) {

        (success,) = _tokenAddress.call(abi.encodeWithSignature("approve(address,uint256)", _spender, _value));
        require(success,  "Approve failed");

        return fetchReturnData();
    }

    function fetchReturnData() internal pure returns (bool success){

        assembly {
            switch returndatasize()
            case 0 {
                success := 1
            }
            case 32 {
                returndatacopy(0, 0, 32)
                success := mload(0)
            }
            default {
                revert(0, 0)
            }
        }
    }

}


library Utils {


    uint256 constant internal PRECISION = (10**18);
    uint256 constant internal MAX_QTY   = (10**28); // 10B tokens
    uint256 constant internal MAX_RATE  = (PRECISION * 10**6); // up to 1M tokens per ETH
    uint256 constant internal MAX_DECIMALS = 18;
    uint256 constant internal ETH_DECIMALS = 18;
    uint256 constant internal MAX_UINT = 2**256-1;
    address constant internal ETH_ADDRESS = address(0x0);

    function precision() internal pure returns (uint256) { return PRECISION; }

    function max_qty() internal pure returns (uint256) { return MAX_QTY; }

    function max_rate() internal pure returns (uint256) { return MAX_RATE; }

    function max_decimals() internal pure returns (uint256) { return MAX_DECIMALS; }

    function eth_decimals() internal pure returns (uint256) { return ETH_DECIMALS; }

    function max_uint() internal pure returns (uint256) { return MAX_UINT; }

    function eth_address() internal pure returns (address) { return ETH_ADDRESS; }


    function getDecimals(address token)
        internal
        returns (uint256 decimals)
    {

        bytes4 functionSig = bytes4(keccak256("decimals()"));

        assembly {
            let ptr := mload(0x40)
            mstore(ptr,functionSig)
            let functionSigLength := 0x04
            let wordLength := 0x20

            let success := call(
                                gas, // Amount of gas
                                token, // Address to call
                                0, // ether to send
                                ptr, // ptr to input data
                                functionSigLength, // size of data
                                ptr, // where to store output data (overwrite input)
                                wordLength // size of output data (32 bytes)
                               )

            switch success
            case 0 {
                decimals := 0 // If the token doesn't implement `decimals()`, return 0 as default
            }
            case 1 {
                decimals := mload(ptr) // Set decimals to return data from call
            }
            mstore(0x40,add(ptr,0x04)) // Reset the free memory pointer to the next known free location
        }
    }

    function tokenAllowanceAndBalanceSet(
        address tokenOwner,
        address tokenAddress,
        uint256 tokenAmount,
        address addressToAllow
    )
        internal
        view
        returns (bool)
    {

        return (
            ERC20(tokenAddress).allowance(tokenOwner, addressToAllow) >= tokenAmount &&
            ERC20(tokenAddress).balanceOf(tokenOwner) >= tokenAmount
        );
    }

    function calcDstQty(uint srcQty, uint srcDecimals, uint dstDecimals, uint rate) internal pure returns (uint) {

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS);
            return (srcQty * rate * (10**(dstDecimals - srcDecimals))) / PRECISION;
        } else {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS);
            return (srcQty * rate) / (PRECISION * (10**(srcDecimals - dstDecimals)));
        }
    }

    function calcSrcQty(uint dstQty, uint srcDecimals, uint dstDecimals, uint rate) internal pure returns (uint) {


        uint numerator;
        uint denominator;
        if (srcDecimals >= dstDecimals) {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS);
            numerator = (PRECISION * dstQty * (10**(srcDecimals - dstDecimals)));
            denominator = rate;
        } else {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS);
            numerator = (PRECISION * dstQty);
            denominator = (rate * (10**(dstDecimals - srcDecimals)));
        }
        return (numerator + denominator - 1) / denominator; //avoid rounding down errors
    }

    function calcDestAmount(ERC20 src, ERC20 dest, uint srcAmount, uint rate) internal returns (uint) {

        return calcDstQty(srcAmount, getDecimals(address(src)), getDecimals(address(dest)), rate);
    }

    function calcSrcAmount(ERC20 src, ERC20 dest, uint destAmount, uint rate) internal returns (uint) {

        return calcSrcQty(destAmount, getDecimals(address(src)), getDecimals(address(dest)), rate);
    }

    function calcRateFromQty(uint srcAmount, uint destAmount, uint srcDecimals, uint dstDecimals)
        internal pure returns (uint)
    {

        require(srcAmount <= MAX_QTY);
        require(destAmount <= MAX_QTY);

        if (dstDecimals >= srcDecimals) {
            require((dstDecimals - srcDecimals) <= MAX_DECIMALS);
            return (destAmount * PRECISION / ((10 ** (dstDecimals - srcDecimals)) * srcAmount));
        } else {
            require((srcDecimals - dstDecimals) <= MAX_DECIMALS);
            return (destAmount * PRECISION * (10 ** (srcDecimals - dstDecimals)) / srcAmount);
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {

        return a < b ? a : b;
    }
}

contract Ownable {

  address payable public owner;


  event OwnershipRenounced(address indexed previousOwner);
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );


  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {

    require(msg.sender == owner);
    _;
  }

  function renounceOwnership() public onlyOwner {

    emit OwnershipRenounced(owner);
    owner = address(0);
  }

  function transferOwnership(address payable _newOwner) public onlyOwner {

    _transferOwnership(_newOwner);
  }

  function _transferOwnership(address payable _newOwner) internal {

    require(_newOwner != address(0));
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }
}

contract Pausable is Ownable {

  event Paused();
  event Unpaused();

  bool private _paused = false;

  function paused() public view returns (bool) {

    return _paused;
  }

  modifier whenNotPaused() {

    require(!_paused, "Contract is paused.");
    _;
  }

  modifier whenPaused() {

    require(_paused, "Contract not paused.");
    _;
  }

  function pause() public onlyOwner whenNotPaused {

    _paused = true;
    emit Paused();
  }

  function unpause() public onlyOwner whenPaused {

    _paused = false;
    emit Unpaused();
  }
}

contract PartnerRegistry is Ownable, Pausable {


    address target;
    mapping(address => bool) partnerContracts;
    address payable public companyBeneficiary;
    uint256 public basePercentage;
    PartnerRegistry public previousRegistry;

    event PartnerRegistered(address indexed creator, address indexed beneficiary, address partnerContract);

    constructor(PartnerRegistry _previousRegistry, address _target, address payable _companyBeneficiary, uint256 _basePercentage) public {
        previousRegistry = _previousRegistry;
        target = _target;
        companyBeneficiary = _companyBeneficiary;
        basePercentage = _basePercentage;
    }

    function registerPartner(address payable partnerBeneficiary, uint256 partnerPercentage) whenNotPaused external {

        Partner newPartner = Partner(createClone());
        newPartner.init(this,address(0x0000000000000000000000000000000000000000), 0, partnerBeneficiary, partnerPercentage);
        partnerContracts[address(newPartner)] = true;
        emit PartnerRegistered(address(msg.sender), partnerBeneficiary, address(newPartner));
    }

    function overrideRegisterPartner(
        address payable _companyBeneficiary,
        uint256 _companyPercentage,
        address payable partnerBeneficiary,
        uint256 partnerPercentage
    ) external onlyOwner {

        Partner newPartner = Partner(createClone());
        newPartner.init(PartnerRegistry(0x0000000000000000000000000000000000000000), _companyBeneficiary, _companyPercentage, partnerBeneficiary, partnerPercentage);
        partnerContracts[address(newPartner)] = true;
        emit PartnerRegistered(address(msg.sender), partnerBeneficiary, address(newPartner));
    }

    function deletePartner(address _partnerAddress) external onlyOwner {

        partnerContracts[_partnerAddress] = false;
    }

    function createClone() internal returns (address payable result) {

        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, clone, 0x37)
        }
    }

    function isValidPartner(address partnerContract) external view returns(bool) {

        return partnerContracts[partnerContract] || previousRegistry.isValidPartner(partnerContract);
    }

    function updateCompanyInfo(address payable newCompanyBeneficiary, uint256 newBasePercentage) external onlyOwner {

        companyBeneficiary = newCompanyBeneficiary;
        basePercentage = newBasePercentage;
    }
}


library Math {

  function max(uint256 a, uint256 b) internal pure returns (uint256) {

    return a >= b ? a : b;
  }

  function min(uint256 a, uint256 b) internal pure returns (uint256) {

    return a < b ? a : b;
  }

  function average(uint256 a, uint256 b) internal pure returns (uint256) {

    return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);
  }
}

contract Partner {


    address payable public partnerBeneficiary;
    uint256 public partnerPercentage; //This is out of 1 ETH, e.g. 0.5 ETH is 50% of the fee

    uint256 public overrideCompanyPercentage;
    address payable public overrideCompanyBeneficiary;

    PartnerRegistry public registry;

    event LogPayout(
        address[] tokens,
        uint256[] amount
    );

    function init(
        PartnerRegistry _registry,
        address payable _overrideCompanyBeneficiary,
        uint256 _overrideCompanyPercentage,
        address payable _partnerBeneficiary,
        uint256 _partnerPercentage
    ) public {

        require(registry == PartnerRegistry(0x0000000000000000000000000000000000000000) &&
          overrideCompanyBeneficiary == address(0x0) && partnerBeneficiary == address(0x0)
        );
        overrideCompanyBeneficiary = _overrideCompanyBeneficiary;
        overrideCompanyPercentage = _overrideCompanyPercentage;
        partnerBeneficiary = _partnerBeneficiary;
        partnerPercentage = _partnerPercentage;
        overrideCompanyPercentage = _overrideCompanyPercentage;
        registry = _registry;
    }

    function payout(
        address[] memory tokens
    ) public {

        uint totalFeePercentage = getTotalFeePercentage();
        address payable companyBeneficiary = companyBeneficiary();
        uint256[] memory amountsPaidOut = new uint256[](tokens.length);
        for(uint256 index = 0; index<tokens.length; index++){
            uint256 balance = tokens[index] == Utils.eth_address() ? address(this).balance : ERC20(tokens[index]).balanceOf(address(this));
            amountsPaidOut[index] = balance;
            uint256 partnerAmount = SafeMath.div(SafeMath.mul(balance, partnerPercentage), getTotalFeePercentage());
            uint256 companyAmount = balance - partnerAmount;
            if(tokens[index] == Utils.eth_address()){
                partnerBeneficiary.transfer(partnerAmount);
                companyBeneficiary.transfer(companyAmount);
            } else {
                ERC20SafeTransfer.safeTransfer(tokens[index], partnerBeneficiary, partnerAmount);
                ERC20SafeTransfer.safeTransfer(tokens[index], companyBeneficiary, companyAmount);
            }
        }
	    emit LogPayout(tokens,amountsPaidOut);
    }

    function getTotalFeePercentage() public view returns (uint256){

        return partnerPercentage + companyPercentage();
    }

    function companyPercentage() public view returns (uint256){

        if(registry != PartnerRegistry(0x0000000000000000000000000000000000000000)){
            return Math.max(registry.basePercentage(), partnerPercentage);
        } else {
            return overrideCompanyPercentage;
        }
    }

    function companyBeneficiary() public view returns (address payable) {

        if(registry != PartnerRegistry(0x0000000000000000000000000000000000000000)){
            return registry.companyBeneficiary();
        } else {
            return overrideCompanyBeneficiary;
        }    
    }

    function() external payable {

    }
}