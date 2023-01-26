

pragma solidity ^0.5.0;

contract Ownable {

    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () internal {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    function owner() public view returns (address) {

        return _owner;
    }

    modifier onlyOwner() {

        require(isOwner());
        _;
    }

    function isOwner() public view returns (bool) {

        return msg.sender == _owner;
    }

    function renounceOwnership() public onlyOwner {

        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public onlyOwner {

        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {

        require(newOwner != address(0));
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}


pragma solidity ^0.5.4;




contract Reputation is Ownable {


    uint8 public decimals = 18;             //Number of decimals of the smallest unit
    event Mint(address indexed _to, uint256 _amount);
    event Burn(address indexed _from, uint256 _amount);

    struct Checkpoint {

        uint128 fromBlock;

        uint128 value;
    }

    mapping (address => Checkpoint[]) balances;

    Checkpoint[] totalSupplyHistory;

    constructor(
    ) public
    {
    }

    function totalSupply() public view returns (uint256) {

        return totalSupplyAt(block.number);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {

        return balanceOfAt(_owner, block.number);
    }

    function balanceOfAt(address _owner, uint256 _blockNumber)
    public view returns (uint256)
    {

        if ((balances[_owner].length == 0) || (balances[_owner][0].fromBlock > _blockNumber)) {
            return 0;
        } else {
            return getValueAt(balances[_owner], _blockNumber);
        }
    }

    function totalSupplyAt(uint256 _blockNumber) public view returns(uint256) {

        if ((totalSupplyHistory.length == 0) || (totalSupplyHistory[0].fromBlock > _blockNumber)) {
            return 0;
        } else {
            return getValueAt(totalSupplyHistory, _blockNumber);
        }
    }

    function mint(address _user, uint256 _amount) public onlyOwner returns (bool) {

        uint256 curTotalSupply = totalSupply();
        require(curTotalSupply + _amount >= curTotalSupply); // Check for overflow
        uint256 previousBalanceTo = balanceOf(_user);
        require(previousBalanceTo + _amount >= previousBalanceTo); // Check for overflow
        updateValueAtNow(totalSupplyHistory, curTotalSupply + _amount);
        updateValueAtNow(balances[_user], previousBalanceTo + _amount);
        emit Mint(_user, _amount);
        return true;
    }

    function burn(address _user, uint256 _amount) public onlyOwner returns (bool) {

        uint256 curTotalSupply = totalSupply();
        uint256 amountBurned = _amount;
        uint256 previousBalanceFrom = balanceOf(_user);
        if (previousBalanceFrom < amountBurned) {
            amountBurned = previousBalanceFrom;
        }
        updateValueAtNow(totalSupplyHistory, curTotalSupply - amountBurned);
        updateValueAtNow(balances[_user], previousBalanceFrom - amountBurned);
        emit Burn(_user, amountBurned);
        return true;
    }


    function getValueAt(Checkpoint[] storage checkpoints, uint256 _block) internal view returns (uint256) {

        if (checkpoints.length == 0) {
            return 0;
        }

        if (_block >= checkpoints[checkpoints.length-1].fromBlock) {
            return checkpoints[checkpoints.length-1].value;
        }
        if (_block < checkpoints[0].fromBlock) {
            return 0;
        }

        uint256 min = 0;
        uint256 max = checkpoints.length-1;
        while (max > min) {
            uint256 mid = (max + min + 1) / 2;
            if (checkpoints[mid].fromBlock<=_block) {
                min = mid;
            } else {
                max = mid-1;
            }
        }
        return checkpoints[min].value;
    }

    function updateValueAtNow(Checkpoint[] storage checkpoints, uint256 _value) internal {

        require(uint128(_value) == _value); //check value is in the 128 bits bounderies
        if ((checkpoints.length == 0) || (checkpoints[checkpoints.length - 1].fromBlock < block.number)) {
            Checkpoint storage newCheckPoint = checkpoints[checkpoints.length++];
            newCheckPoint.fromBlock = uint128(block.number);
            newCheckPoint.value = uint128(_value);
        } else {
            Checkpoint storage oldCheckPoint = checkpoints[checkpoints.length-1];
            oldCheckPoint.value = uint128(_value);
        }
    }
}


pragma solidity ^0.5.0;

interface IERC20 {

    function transfer(address to, uint256 value) external returns (bool);


    function approve(address spender, uint256 value) external returns (bool);


    function transferFrom(address from, address to, uint256 value) external returns (bool);


    function totalSupply() external view returns (uint256);


    function balanceOf(address who) external view returns (uint256);


    function allowance(address owner, address spender) external view returns (uint256);


    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}


pragma solidity ^0.5.0;

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


pragma solidity ^0.5.0;



contract ERC20 is IERC20 {

    using SafeMath for uint256;

    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowed;

    uint256 private _totalSupply;

    function totalSupply() public view returns (uint256) {

        return _totalSupply;
    }

    function balanceOf(address owner) public view returns (uint256) {

        return _balances[owner];
    }

    function allowance(address owner, address spender) public view returns (uint256) {

        return _allowed[owner][spender];
    }

    function transfer(address to, uint256 value) public returns (bool) {

        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {

        require(spender != address(0));

        _allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {

        _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(value);
        _transfer(from, to, value);
        emit Approval(from, msg.sender, _allowed[from][msg.sender]);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {

        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {

        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].sub(subtractedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {

        require(to != address(0));

        _balances[from] = _balances[from].sub(value);
        _balances[to] = _balances[to].add(value);
        emit Transfer(from, to, value);
    }

    function _mint(address account, uint256 value) internal {

        require(account != address(0));

        _totalSupply = _totalSupply.add(value);
        _balances[account] = _balances[account].add(value);
        emit Transfer(address(0), account, value);
    }

    function _burn(address account, uint256 value) internal {

        require(account != address(0));

        _totalSupply = _totalSupply.sub(value);
        _balances[account] = _balances[account].sub(value);
        emit Transfer(account, address(0), value);
    }

    function _burnFrom(address account, uint256 value) internal {

        _allowed[account][msg.sender] = _allowed[account][msg.sender].sub(value);
        _burn(account, value);
        emit Approval(account, msg.sender, _allowed[account][msg.sender]);
    }
}


pragma solidity ^0.5.0;


contract ERC20Burnable is ERC20 {

    function burn(uint256 value) public {

        _burn(msg.sender, value);
    }

    function burnFrom(address from, uint256 value) public {

        _burnFrom(from, value);
    }
}


pragma solidity ^0.5.4;






contract DAOToken is ERC20, ERC20Burnable, Ownable {


    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public cap;

    constructor(string memory _name, string memory _symbol, uint256 _cap)
    public {
        name = _name;
        symbol = _symbol;
        cap = _cap;
    }

    function mint(address _to, uint256 _amount) public onlyOwner returns (bool) {

        if (cap > 0)
            require(totalSupply().add(_amount) <= cap);
        _mint(_to, _amount);
        return true;
    }
}


pragma solidity ^0.5.0;

library Address {

    function isContract(address account) internal view returns (bool) {

        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}


pragma solidity ^0.5.4;



library SafeERC20 {

    using Address for address;

    bytes4 constant private TRANSFER_SELECTOR = bytes4(keccak256(bytes("transfer(address,uint256)")));
    bytes4 constant private TRANSFERFROM_SELECTOR = bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));
    bytes4 constant private APPROVE_SELECTOR = bytes4(keccak256(bytes("approve(address,uint256)")));

    function safeTransfer(address _erc20Addr, address _to, uint256 _value) internal {


        require(_erc20Addr.isContract());

        (bool success, bytes memory returnValue) =
        _erc20Addr.call(abi.encodeWithSelector(TRANSFER_SELECTOR, _to, _value));
        require(success);
        require(returnValue.length == 0 || (returnValue.length == 32 && (returnValue[31] != 0)));
    }

    function safeTransferFrom(address _erc20Addr, address _from, address _to, uint256 _value) internal {


        require(_erc20Addr.isContract());

        (bool success, bytes memory returnValue) =
        _erc20Addr.call(abi.encodeWithSelector(TRANSFERFROM_SELECTOR, _from, _to, _value));
        require(success);
        require(returnValue.length == 0 || (returnValue.length == 32 && (returnValue[31] != 0)));
    }

    function safeApprove(address _erc20Addr, address _spender, uint256 _value) internal {


        require(_erc20Addr.isContract());

        require((_value == 0) || (IERC20(_erc20Addr).allowance(address(this), _spender) == 0));

        (bool success, bytes memory returnValue) =
        _erc20Addr.call(abi.encodeWithSelector(APPROVE_SELECTOR, _spender, _value));
        require(success);
        require(returnValue.length == 0 || (returnValue.length == 32 && (returnValue[31] != 0)));
    }
}


pragma solidity ^0.5.4;







contract Avatar is Ownable {

    using SafeERC20 for address;

    string public orgName;
    DAOToken public nativeToken;
    Reputation public nativeReputation;

    event GenericCall(address indexed _contract, bytes _data, uint _value, bool _success);
    event SendEther(uint256 _amountInWei, address indexed _to);
    event ExternalTokenTransfer(address indexed _externalToken, address indexed _to, uint256 _value);
    event ExternalTokenTransferFrom(address indexed _externalToken, address _from, address _to, uint256 _value);
    event ExternalTokenApproval(address indexed _externalToken, address _spender, uint256 _value);
    event ReceiveEther(address indexed _sender, uint256 _value);
    event MetaData(string _metaData);

    constructor(string memory _orgName, DAOToken _nativeToken, Reputation _nativeReputation) public {
        orgName = _orgName;
        nativeToken = _nativeToken;
        nativeReputation = _nativeReputation;
    }

    function() external payable {
        emit ReceiveEther(msg.sender, msg.value);
    }

    function genericCall(address _contract, bytes memory _data, uint256 _value)
    public
    onlyOwner
    returns(bool success, bytes memory returnValue) {

        (success, returnValue) = _contract.call.value(_value)(_data);
        emit GenericCall(_contract, _data, _value, success);
    }

    function sendEther(uint256 _amountInWei, address payable _to) public onlyOwner returns(bool) {

        _to.transfer(_amountInWei);
        emit SendEther(_amountInWei, _to);
        return true;
    }

    function externalTokenTransfer(IERC20 _externalToken, address _to, uint256 _value)
    public onlyOwner returns(bool)
    {

        address(_externalToken).safeTransfer(_to, _value);
        emit ExternalTokenTransfer(address(_externalToken), _to, _value);
        return true;
    }

    function externalTokenTransferFrom(
        IERC20 _externalToken,
        address _from,
        address _to,
        uint256 _value
    )
    public onlyOwner returns(bool)
    {

        address(_externalToken).safeTransferFrom(_from, _to, _value);
        emit ExternalTokenTransferFrom(address(_externalToken), _from, _to, _value);
        return true;
    }

    function externalTokenApproval(IERC20 _externalToken, address _spender, uint256 _value)
    public onlyOwner returns(bool)
    {

        address(_externalToken).safeApprove(_spender, _value);
        emit ExternalTokenApproval(address(_externalToken), _spender, _value);
        return true;
    }

    function metaData(string memory _metaData) public onlyOwner returns(bool) {

        emit MetaData(_metaData);
        return true;
    }


}


pragma solidity ^0.5.4;


contract GlobalConstraintInterface {


    enum CallPhase { Pre, Post, PreAndPost }

    function pre( address _scheme, bytes32 _params, bytes32 _method ) public returns(bool);

    function post( address _scheme, bytes32 _params, bytes32 _method ) public returns(bool);

    function when() public returns(CallPhase);

}


pragma solidity ^0.5.4;



interface ControllerInterface {


    function mintReputation(uint256 _amount, address _to, address _avatar)
    external
    returns(bool);


    function burnReputation(uint256 _amount, address _from, address _avatar)
    external
    returns(bool);


    function mintTokens(uint256 _amount, address _beneficiary, address _avatar)
    external
    returns(bool);


    function registerScheme(address _scheme, bytes32 _paramsHash, bytes4 _permissions, address _avatar)
    external
    returns(bool);


    function unregisterScheme(address _scheme, address _avatar)
    external
    returns(bool);


    function unregisterSelf(address _avatar) external returns(bool);


    function addGlobalConstraint(address _globalConstraint, bytes32 _params, address _avatar)
    external returns(bool);


    function removeGlobalConstraint (address _globalConstraint, address _avatar)
    external  returns(bool);

    function upgradeController(address _newController, Avatar _avatar)
    external returns(bool);


    function genericCall(address _contract, bytes calldata _data, Avatar _avatar, uint256 _value)
    external
    returns(bool, bytes memory);


    function sendEther(uint256 _amountInWei, address payable _to, Avatar _avatar)
    external returns(bool);


    function externalTokenTransfer(IERC20 _externalToken, address _to, uint256 _value, Avatar _avatar)
    external
    returns(bool);


    function externalTokenTransferFrom(
    IERC20 _externalToken,
    address _from,
    address _to,
    uint256 _value,
    Avatar _avatar)
    external
    returns(bool);


    function externalTokenApproval(IERC20 _externalToken, address _spender, uint256 _value, Avatar _avatar)
    external
    returns(bool);


    function metaData(string calldata _metaData, Avatar _avatar) external returns(bool);


    function getNativeReputation(address _avatar)
    external
    view
    returns(address);


    function isSchemeRegistered( address _scheme, address _avatar) external view returns(bool);


    function getSchemeParameters(address _scheme, address _avatar) external view returns(bytes32);


    function getGlobalConstraintParameters(address _globalConstraint, address _avatar) external view returns(bytes32);


    function getSchemePermissions(address _scheme, address _avatar) external view returns(bytes4);


    function globalConstraintsCount(address _avatar) external view returns(uint, uint);


    function isGlobalConstraintRegistered(address _globalConstraint, address _avatar) external view returns(bool);

}


pragma solidity ^0.5.4;





contract Controller is ControllerInterface {


    struct Scheme {
        bytes32 paramsHash;  // a hash "configuration" of the scheme
        bytes4  permissions; // A bitwise flags of permissions,
    }

    struct GlobalConstraint {
        address gcAddress;
        bytes32 params;
    }

    struct GlobalConstraintRegister {
        bool isRegistered; //is registered
        uint256 index;    //index at globalConstraints
    }

    mapping(address=>Scheme) public schemes;

    Avatar public avatar;
    DAOToken public nativeToken;
    Reputation public nativeReputation;
    address public newController;

    GlobalConstraint[] public globalConstraintsPre;
    GlobalConstraint[] public globalConstraintsPost;
    mapping(address=>GlobalConstraintRegister) public globalConstraintsRegisterPre;
    mapping(address=>GlobalConstraintRegister) public globalConstraintsRegisterPost;

    event MintReputation (address indexed _sender, address indexed _to, uint256 _amount);
    event BurnReputation (address indexed _sender, address indexed _from, uint256 _amount);
    event MintTokens (address indexed _sender, address indexed _beneficiary, uint256 _amount);
    event RegisterScheme (address indexed _sender, address indexed _scheme);
    event UnregisterScheme (address indexed _sender, address indexed _scheme);
    event UpgradeController(address indexed _oldController, address _newController);

    event AddGlobalConstraint(
        address indexed _globalConstraint,
        bytes32 _params,
        GlobalConstraintInterface.CallPhase _when);

    event RemoveGlobalConstraint(address indexed _globalConstraint, uint256 _index, bool _isPre);

    constructor( Avatar _avatar) public {
        avatar = _avatar;
        nativeToken = avatar.nativeToken();
        nativeReputation = avatar.nativeReputation();
        schemes[msg.sender] = Scheme({paramsHash: bytes32(0), permissions: bytes4(0x0000001F)});
    }

    function() external {
        revert();
    }

    modifier onlyRegisteredScheme() {

        require(schemes[msg.sender].permissions&bytes4(0x00000001) == bytes4(0x00000001));
        _;
    }

    modifier onlyRegisteringSchemes() {

        require(schemes[msg.sender].permissions&bytes4(0x00000002) == bytes4(0x00000002));
        _;
    }

    modifier onlyGlobalConstraintsScheme() {

        require(schemes[msg.sender].permissions&bytes4(0x00000004) == bytes4(0x00000004));
        _;
    }

    modifier onlyUpgradingScheme() {

        require(schemes[msg.sender].permissions&bytes4(0x00000008) == bytes4(0x00000008));
        _;
    }

    modifier onlyGenericCallScheme() {

        require(schemes[msg.sender].permissions&bytes4(0x00000010) == bytes4(0x00000010));
        _;
    }

    modifier onlyMetaDataScheme() {

        require(schemes[msg.sender].permissions&bytes4(0x00000010) == bytes4(0x00000010));
        _;
    }

    modifier onlySubjectToConstraint(bytes32 func) {

        uint256 idx;
        for (idx = 0; idx < globalConstraintsPre.length; idx++) {
            require(
            (GlobalConstraintInterface(globalConstraintsPre[idx].gcAddress))
            .pre(msg.sender, globalConstraintsPre[idx].params, func));
        }
        _;
        for (idx = 0; idx < globalConstraintsPost.length; idx++) {
            require(
            (GlobalConstraintInterface(globalConstraintsPost[idx].gcAddress))
            .post(msg.sender, globalConstraintsPost[idx].params, func));
        }
    }

    modifier isAvatarValid(address _avatar) {

        require(_avatar == address(avatar));
        _;
    }

    function mintReputation(uint256 _amount, address _to, address _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("mintReputation")
    isAvatarValid(_avatar)
    returns(bool)
    {

        emit MintReputation(msg.sender, _to, _amount);
        return nativeReputation.mint(_to, _amount);
    }

    function burnReputation(uint256 _amount, address _from, address _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("burnReputation")
    isAvatarValid(_avatar)
    returns(bool)
    {

        emit BurnReputation(msg.sender, _from, _amount);
        return nativeReputation.burn(_from, _amount);
    }

    function mintTokens(uint256 _amount, address _beneficiary, address _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("mintTokens")
    isAvatarValid(_avatar)
    returns(bool)
    {

        emit MintTokens(msg.sender, _beneficiary, _amount);
        return nativeToken.mint(_beneficiary, _amount);
    }

    function registerScheme(address _scheme, bytes32 _paramsHash, bytes4 _permissions, address _avatar)
    external
    onlyRegisteringSchemes
    onlySubjectToConstraint("registerScheme")
    isAvatarValid(_avatar)
    returns(bool)
    {


        Scheme memory scheme = schemes[_scheme];


        require(bytes4(0x0000001f)&(_permissions^scheme.permissions)&(~schemes[msg.sender].permissions) == bytes4(0));

        require(bytes4(0x0000001f)&(scheme.permissions&(~schemes[msg.sender].permissions)) == bytes4(0));

        schemes[_scheme].paramsHash = _paramsHash;
        schemes[_scheme].permissions = _permissions|bytes4(0x00000001);
        emit RegisterScheme(msg.sender, _scheme);
        return true;
    }

    function unregisterScheme( address _scheme, address _avatar)
    external
    onlyRegisteringSchemes
    onlySubjectToConstraint("unregisterScheme")
    isAvatarValid(_avatar)
    returns(bool)
    {

        if (_isSchemeRegistered(_scheme) == false) {
            return false;
        }
        require(bytes4(0x0000001f)&(schemes[_scheme].permissions&(~schemes[msg.sender].permissions)) == bytes4(0));

        emit UnregisterScheme(msg.sender, _scheme);
        delete schemes[_scheme];
        return true;
    }

    function unregisterSelf(address _avatar) external isAvatarValid(_avatar) returns(bool) {

        if (_isSchemeRegistered(msg.sender) == false) {
            return false;
        }
        delete schemes[msg.sender];
        emit UnregisterScheme(msg.sender, msg.sender);
        return true;
    }

    function addGlobalConstraint(address _globalConstraint, bytes32 _params, address _avatar)
    external
    onlyGlobalConstraintsScheme
    isAvatarValid(_avatar)
    returns(bool)
    {

        GlobalConstraintInterface.CallPhase when = GlobalConstraintInterface(_globalConstraint).when();
        if ((when == GlobalConstraintInterface.CallPhase.Pre)||
            (when == GlobalConstraintInterface.CallPhase.PreAndPost)) {
            if (!globalConstraintsRegisterPre[_globalConstraint].isRegistered) {
                globalConstraintsPre.push(GlobalConstraint(_globalConstraint, _params));
                globalConstraintsRegisterPre[_globalConstraint] =
                GlobalConstraintRegister(true, globalConstraintsPre.length-1);
            }else {
                globalConstraintsPre[globalConstraintsRegisterPre[_globalConstraint].index].params = _params;
            }
        }
        if ((when == GlobalConstraintInterface.CallPhase.Post)||
            (when == GlobalConstraintInterface.CallPhase.PreAndPost)) {
            if (!globalConstraintsRegisterPost[_globalConstraint].isRegistered) {
                globalConstraintsPost.push(GlobalConstraint(_globalConstraint, _params));
                globalConstraintsRegisterPost[_globalConstraint] =
                GlobalConstraintRegister(true, globalConstraintsPost.length-1);
            }else {
                globalConstraintsPost[globalConstraintsRegisterPost[_globalConstraint].index].params = _params;
            }
        }
        emit AddGlobalConstraint(_globalConstraint, _params, when);
        return true;
    }

    function removeGlobalConstraint (address _globalConstraint, address _avatar)
    external
    onlyGlobalConstraintsScheme
    isAvatarValid(_avatar)
    returns(bool)
    {
        GlobalConstraintRegister memory globalConstraintRegister;
        GlobalConstraint memory globalConstraint;
        GlobalConstraintInterface.CallPhase when = GlobalConstraintInterface(_globalConstraint).when();
        bool retVal = false;

        if ((when == GlobalConstraintInterface.CallPhase.Pre)||
            (when == GlobalConstraintInterface.CallPhase.PreAndPost)) {
            globalConstraintRegister = globalConstraintsRegisterPre[_globalConstraint];
            if (globalConstraintRegister.isRegistered) {
                if (globalConstraintRegister.index < globalConstraintsPre.length-1) {
                    globalConstraint = globalConstraintsPre[globalConstraintsPre.length-1];
                    globalConstraintsPre[globalConstraintRegister.index] = globalConstraint;
                    globalConstraintsRegisterPre[globalConstraint.gcAddress].index = globalConstraintRegister.index;
                }
                globalConstraintsPre.length--;
                delete globalConstraintsRegisterPre[_globalConstraint];
                retVal = true;
            }
        }
        if ((when == GlobalConstraintInterface.CallPhase.Post)||
            (when == GlobalConstraintInterface.CallPhase.PreAndPost)) {
            globalConstraintRegister = globalConstraintsRegisterPost[_globalConstraint];
            if (globalConstraintRegister.isRegistered) {
                if (globalConstraintRegister.index < globalConstraintsPost.length-1) {
                    globalConstraint = globalConstraintsPost[globalConstraintsPost.length-1];
                    globalConstraintsPost[globalConstraintRegister.index] = globalConstraint;
                    globalConstraintsRegisterPost[globalConstraint.gcAddress].index = globalConstraintRegister.index;
                }
                globalConstraintsPost.length--;
                delete globalConstraintsRegisterPost[_globalConstraint];
                retVal = true;
            }
        }
        if (retVal) {
            emit RemoveGlobalConstraint(
            _globalConstraint,
            globalConstraintRegister.index,
            when == GlobalConstraintInterface.CallPhase.Pre
            );
        }
        return retVal;
    }

    function upgradeController(address _newController, Avatar _avatar)
    external
    onlyUpgradingScheme
    isAvatarValid(address(_avatar))
    returns(bool)
    {

        require(newController == address(0));   // so the upgrade could be done once for a contract.
        require(_newController != address(0));
        newController = _newController;
        avatar.transferOwnership(_newController);
        require(avatar.owner() == _newController);
        if (nativeToken.owner() == address(this)) {
            nativeToken.transferOwnership(_newController);
            require(nativeToken.owner() == _newController);
        }
        if (nativeReputation.owner() == address(this)) {
            nativeReputation.transferOwnership(_newController);
            require(nativeReputation.owner() == _newController);
        }
        emit UpgradeController(address(this), newController);
        return true;
    }

    function genericCall(address _contract, bytes calldata _data, Avatar _avatar, uint256 _value)
    external
    onlyGenericCallScheme
    onlySubjectToConstraint("genericCall")
    isAvatarValid(address(_avatar))
    returns (bool, bytes memory)
    {

        return avatar.genericCall(_contract, _data, _value);
    }

    function sendEther(uint256 _amountInWei, address payable _to, Avatar _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("sendEther")
    isAvatarValid(address(_avatar))
    returns(bool)
    {

        return avatar.sendEther(_amountInWei, _to);
    }

    function externalTokenTransfer(IERC20 _externalToken, address _to, uint256 _value, Avatar _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("externalTokenTransfer")
    isAvatarValid(address(_avatar))
    returns(bool)
    {

        return avatar.externalTokenTransfer(_externalToken, _to, _value);
    }

    function externalTokenTransferFrom(
    IERC20 _externalToken,
    address _from,
    address _to,
    uint256 _value,
    Avatar _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("externalTokenTransferFrom")
    isAvatarValid(address(_avatar))
    returns(bool)
    {

        return avatar.externalTokenTransferFrom(_externalToken, _from, _to, _value);
    }

    function externalTokenApproval(IERC20 _externalToken, address _spender, uint256 _value, Avatar _avatar)
    external
    onlyRegisteredScheme
    onlySubjectToConstraint("externalTokenIncreaseApproval")
    isAvatarValid(address(_avatar))
    returns(bool)
    {

        return avatar.externalTokenApproval(_externalToken, _spender, _value);
    }

    function metaData(string calldata _metaData, Avatar _avatar)
        external
        onlyMetaDataScheme
        isAvatarValid(address(_avatar))
        returns(bool)
        {

        return avatar.metaData(_metaData);
    }

    function getNativeReputation(address _avatar) external isAvatarValid(_avatar) view returns(address) {

        return address(nativeReputation);
    }

    function isSchemeRegistered(address _scheme, address _avatar) external isAvatarValid(_avatar) view returns(bool) {

        return _isSchemeRegistered(_scheme);
    }

    function getSchemeParameters(address _scheme, address _avatar)
    external
    isAvatarValid(_avatar)
    view
    returns(bytes32)
    {

        return schemes[_scheme].paramsHash;
    }

    function getSchemePermissions(address _scheme, address _avatar)
    external
    isAvatarValid(_avatar)
    view
    returns(bytes4)
    {

        return schemes[_scheme].permissions;
    }

    function getGlobalConstraintParameters(address _globalConstraint, address) external view returns(bytes32) {


        GlobalConstraintRegister memory register = globalConstraintsRegisterPre[_globalConstraint];

        if (register.isRegistered) {
            return globalConstraintsPre[register.index].params;
        }

        register = globalConstraintsRegisterPost[_globalConstraint];

        if (register.isRegistered) {
            return globalConstraintsPost[register.index].params;
        }
    }

    function globalConstraintsCount(address _avatar)
        external
        isAvatarValid(_avatar)
        view
        returns(uint, uint)
        {

        return (globalConstraintsPre.length, globalConstraintsPost.length);
    }

    function isGlobalConstraintRegistered(address _globalConstraint, address _avatar)
        external
        isAvatarValid(_avatar)
        view
        returns(bool)
        {

        return (globalConstraintsRegisterPre[_globalConstraint].isRegistered ||
                globalConstraintsRegisterPost[_globalConstraint].isRegistered);
    }

    function _isSchemeRegistered(address _scheme) private view returns(bool) {

        return (schemes[_scheme].permissions&bytes4(0x00000001) != bytes4(0));
    }
}


pragma solidity ^0.5.4;

interface IntVoteInterface {

    modifier onlyProposalOwner(bytes32 _proposalId) {revert(); _;}

    modifier votable(bytes32 _proposalId) {revert(); _;}


    event NewProposal(
        bytes32 indexed _proposalId,
        address indexed _organization,
        uint256 _numOfChoices,
        address _proposer,
        bytes32 _paramsHash
    );

    event ExecuteProposal(bytes32 indexed _proposalId,
        address indexed _organization,
        uint256 _decision,
        uint256 _totalReputation
    );

    event VoteProposal(
        bytes32 indexed _proposalId,
        address indexed _organization,
        address indexed _voter,
        uint256 _vote,
        uint256 _reputation
    );

    event CancelProposal(bytes32 indexed _proposalId, address indexed _organization );
    event CancelVoting(bytes32 indexed _proposalId, address indexed _organization, address indexed _voter);

    function propose(
        uint256 _numOfChoices,
        bytes32 _proposalParameters,
        address _proposer,
        address _organization
        ) external returns(bytes32);


    function vote(
        bytes32 _proposalId,
        uint256 _vote,
        uint256 _rep,
        address _voter
    )
    external
    returns(bool);


    function cancelVote(bytes32 _proposalId) external;


    function getNumberOfChoices(bytes32 _proposalId) external view returns(uint256);


    function isVotable(bytes32 _proposalId) external view returns(bool);


    function voteStatus(bytes32 _proposalId, uint256 _choice) external view returns(uint256);


    function isAbstainAllow() external pure returns(bool);


    function getAllowedRangeOfChoices() external pure returns(uint256 min, uint256 max);

}


pragma solidity ^0.5.4;


interface VotingMachineCallbacksInterface {

    function mintReputation(uint256 _amount, address _beneficiary, bytes32 _proposalId) external returns(bool);

    function burnReputation(uint256 _amount, address _owner, bytes32 _proposalId) external returns(bool);


    function stakingTokenTransfer(IERC20 _stakingToken, address _beneficiary, uint256 _amount, bytes32 _proposalId)
    external
    returns(bool);


    function getTotalReputationSupply(bytes32 _proposalId) external view returns(uint256);

    function reputationOf(address _owner, bytes32 _proposalId) external view returns(uint256);

    function balanceOfStakingToken(IERC20 _stakingToken, bytes32 _proposalId) external view returns(uint256);

}


pragma solidity ^0.5.4;


contract UniversalSchemeInterface {


    function getParametersFromController(Avatar _avatar) internal view returns(bytes32);

    
}


pragma solidity ^0.5.4;





contract UniversalScheme is UniversalSchemeInterface {

    function getParametersFromController(Avatar _avatar) internal view returns(bytes32) {

        require(ControllerInterface(_avatar.owner()).isSchemeRegistered(address(this), address(_avatar)),
        "scheme is not registered");
        return ControllerInterface(_avatar.owner()).getSchemeParameters(address(this), address(_avatar));
    }
}


pragma solidity ^0.5.0;


library ECDSA {

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {

        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length != 65) {
            return (address(0));
        }

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(hash, v, r, s);
        }
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}


pragma solidity ^0.5.4;



library RealMath {


    uint256 constant private REAL_BITS = 256;

    uint256 constant private REAL_FBITS = 40;

    uint256 constant private REAL_ONE = uint256(1) << REAL_FBITS;

    function pow(uint256 realBase, uint256 exponent) internal pure returns (uint256) {


        uint256 tempRealBase = realBase;
        uint256 tempExponent = exponent;

        uint256 realResult = REAL_ONE;
        while (tempExponent != 0) {
            if ((tempExponent & 0x1) == 0x1) {
                realResult = mul(realResult, tempRealBase);
            }
            tempExponent = tempExponent >> 1;
            if (tempExponent != 0) {
                tempRealBase = mul(tempRealBase, tempRealBase);
            }
        }

        return realResult;
    }

    function fraction(uint216 numerator, uint216 denominator) internal pure returns (uint256) {

        return div(uint256(numerator) * REAL_ONE, uint256(denominator) * REAL_ONE);
    }

    function mul(uint256 realA, uint256 realB) private pure returns (uint256) {

        uint256 res = realA * realB;
        require(res/realA == realB, "RealMath mul overflow");
        return (res >> REAL_FBITS);
    }

    function div(uint256 realNumerator, uint256 realDenominator) private pure returns (uint256) {

        return uint256((uint256(realNumerator) * REAL_ONE) / uint256(realDenominator));
    }

}


pragma solidity ^0.5.4;

interface ProposalExecuteInterface {

    function executeProposal(bytes32 _proposalId, int _decision) external returns(bool);

}


pragma solidity ^0.5.0;

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


pragma solidity ^0.5.4;











contract GenesisProtocolLogic is IntVoteInterface {

    using SafeMath for uint256;
    using Math for uint256;
    using RealMath for uint216;
    using RealMath for uint256;
    using Address for address;

    enum ProposalState { None, ExpiredInQueue, Executed, Queued, PreBoosted, Boosted, QuietEndingPeriod}
    enum ExecutionState { None, QueueBarCrossed, QueueTimeOut, PreBoostedBarCrossed, BoostedTimeOut, BoostedBarCrossed}

    struct Parameters {
        uint256 queuedVoteRequiredPercentage; // the absolute vote percentages bar.
        uint256 queuedVotePeriodLimit; //the time limit for a proposal to be in an absolute voting mode.
        uint256 boostedVotePeriodLimit; //the time limit for a proposal to be in boost mode.
        uint256 preBoostedVotePeriodLimit; //the time limit for a proposal
        uint256 thresholdConst; //constant  for threshold calculation .
        uint256 limitExponentValue;// an upper limit for numberOfBoostedProposals
        uint256 quietEndingPeriod; //quite ending period
        uint256 proposingRepReward;//proposer reputation reward.
        uint256 votersReputationLossRatio;//Unsuccessful pre booster
        uint256 minimumDaoBounty;
        uint256 daoBountyConst;//The DAO downstake for each proposal is calculate according to the formula
        uint256 activationTime;//the point in time after which proposals can be created.
        address voteOnBehalf;
    }

    struct Voter {
        uint256 vote; // YES(1) ,NO(2)
        uint256 reputation; // amount of voter's reputation
        bool preBoosted;
    }

    struct Staker {
        uint256 vote; // YES(1) ,NO(2)
        uint256 amount; // amount of staker's stake
        uint256 amount4Bounty;// amount of staker's stake used for bounty reward calculation.
    }

    struct Proposal {
        bytes32 organizationId; // the organization unique identifier the proposal is target to.
        address callbacks;    // should fulfill voting callbacks interface.
        ProposalState state;
        uint256 winningVote; //the winning vote.
        address proposer;
        uint256 currentBoostedVotePeriodLimit;
        bytes32 paramsHash;
        uint256 daoBountyRemain; //use for checking sum zero bounty claims.it is set at the proposing time.
        uint256 daoBounty;
        uint256 totalStakes;// Total number of tokens staked which can be redeemable by stakers.
        uint256 confidenceThreshold;
        uint256 expirationCallBountyPercentage;
        uint[3] times; //times[0] - submittedTime
        bool daoRedeemItsWinnings;
        mapping(uint256   =>  uint256    ) votes;
        mapping(uint256   =>  uint256    ) preBoostedVotes;
        mapping(address =>  Voter    ) voters;
        mapping(uint256   =>  uint256    ) stakes;
        mapping(address  => Staker   ) stakers;
    }

    event Stake(bytes32 indexed _proposalId,
        address indexed _organization,
        address indexed _staker,
        uint256 _vote,
        uint256 _amount
    );

    event Redeem(bytes32 indexed _proposalId,
        address indexed _organization,
        address indexed _beneficiary,
        uint256 _amount
    );

    event RedeemDaoBounty(bytes32 indexed _proposalId,
        address indexed _organization,
        address indexed _beneficiary,
        uint256 _amount
    );

    event RedeemReputation(bytes32 indexed _proposalId,
        address indexed _organization,
        address indexed _beneficiary,
        uint256 _amount
    );

    event StateChange(bytes32 indexed _proposalId, ProposalState _proposalState);
    event GPExecuteProposal(bytes32 indexed _proposalId, ExecutionState _executionState);
    event ExpirationCallBounty(bytes32 indexed _proposalId, address indexed _beneficiary, uint256 _amount);
    event ConfidenceLevelChange(bytes32 indexed _proposalId, uint256 _confidenceThreshold);

    mapping(bytes32=>Parameters) public parameters;  // A mapping from hashes to parameters
    mapping(bytes32=>Proposal) public proposals; // Mapping from the ID of the proposal to the proposal itself.
    mapping(bytes32=>uint) public orgBoostedProposalsCnt;
    mapping(bytes32        => address     ) public organizations;
    mapping(bytes32           => uint256              ) public averagesDownstakesOfBoosted;
    uint256 constant public NUM_OF_CHOICES = 2;
    uint256 constant public NO = 2;
    uint256 constant public YES = 1;
    uint256 public proposalsCnt; // Total number of proposals
    IERC20 public stakingToken;
    address constant private GEN_TOKEN_ADDRESS = 0x543Ff227F64Aa17eA132Bf9886cAb5DB55DCAddf;
    uint256 constant private MAX_BOOSTED_PROPOSALS = 4096;

    constructor(IERC20 _stakingToken) public {
        if (address(GEN_TOKEN_ADDRESS).isContract()) {
            stakingToken = IERC20(GEN_TOKEN_ADDRESS);
        } else {
            stakingToken = _stakingToken;
        }
    }

    modifier votable(bytes32 _proposalId) {

        require(_isVotable(_proposalId));
        _;
    }

    function propose(uint256, bytes32 _paramsHash, address _proposer, address _organization)
        external
        returns(bytes32)
    {

        require(now > parameters[_paramsHash].activationTime, "not active yet");
        require(parameters[_paramsHash].queuedVoteRequiredPercentage >= 50);
        bytes32 proposalId = keccak256(abi.encodePacked(this, proposalsCnt));
        proposalsCnt = proposalsCnt.add(1);
        Proposal memory proposal;
        proposal.callbacks = msg.sender;
        proposal.organizationId = keccak256(abi.encodePacked(msg.sender, _organization));

        proposal.state = ProposalState.Queued;
        proposal.times[0] = now;//submitted time
        proposal.currentBoostedVotePeriodLimit = parameters[_paramsHash].boostedVotePeriodLimit;
        proposal.proposer = _proposer;
        proposal.winningVote = NO;
        proposal.paramsHash = _paramsHash;
        if (organizations[proposal.organizationId] == address(0)) {
            if (_organization == address(0)) {
                organizations[proposal.organizationId] = msg.sender;
            } else {
                organizations[proposal.organizationId] = _organization;
            }
        }
        uint256 daoBounty =
        parameters[_paramsHash].daoBountyConst.mul(averagesDownstakesOfBoosted[proposal.organizationId]).div(100);
        if (daoBounty < parameters[_paramsHash].minimumDaoBounty) {
            proposal.daoBountyRemain = parameters[_paramsHash].minimumDaoBounty;
        } else {
            proposal.daoBountyRemain = daoBounty;
        }
        proposal.totalStakes = proposal.daoBountyRemain;
        proposals[proposalId] = proposal;
        proposals[proposalId].stakes[NO] = proposal.daoBountyRemain;//dao downstake on the proposal

        emit NewProposal(proposalId, organizations[proposal.organizationId], NUM_OF_CHOICES, _proposer, _paramsHash);
        return proposalId;
    }

    function executeBoosted(bytes32 _proposalId) external returns(uint256 expirationCallBounty) {

        Proposal storage proposal = proposals[_proposalId];
        require(proposal.state == ProposalState.Boosted || proposal.state == ProposalState.QuietEndingPeriod,
        "proposal state in not Boosted nor QuietEndingPeriod");
        require(_execute(_proposalId), "proposal need to expire");
        uint256 expirationCallBountyPercentage =
        (uint(1).add(now.sub(proposal.currentBoostedVotePeriodLimit.add(proposal.times[1])).div(15)));
        if (expirationCallBountyPercentage > 100) {
            expirationCallBountyPercentage = 100;
        }
        proposal.expirationCallBountyPercentage = expirationCallBountyPercentage;
        expirationCallBounty = expirationCallBountyPercentage.mul(proposal.stakes[YES]).div(100);
        require(stakingToken.transfer(msg.sender, expirationCallBounty), "transfer to msg.sender failed");
        emit ExpirationCallBounty(_proposalId, msg.sender, expirationCallBounty);
    }

    function setParameters(
        uint[11] calldata _params, //use array here due to stack too deep issue.
        address _voteOnBehalf
    )
    external
    returns(bytes32)
    {

        require(_params[0] <= 100 && _params[0] >= 50, "50 <= queuedVoteRequiredPercentage <= 100");
        require(_params[4] <= 16000 && _params[4] > 1000, "1000 < thresholdConst <= 16000");
        require(_params[7] <= 100, "votersReputationLossRatio <= 100");
        require(_params[2] >= _params[5], "boostedVotePeriodLimit >= quietEndingPeriod");
        require(_params[8] > 0, "minimumDaoBounty should be > 0");
        require(_params[9] > 0, "daoBountyConst should be > 0");

        bytes32 paramsHash = getParametersHash(_params, _voteOnBehalf);
        uint256 limitExponent = 172;//for alpha less or equal 2
        uint256 j = 2;
        for (uint256 i = 2000; i < 16000; i = i*2) {
            if ((_params[4] > i) && (_params[4] <= i*2)) {
                limitExponent = limitExponent/j;
                break;
            }
            j++;
        }

        parameters[paramsHash] = Parameters({
            queuedVoteRequiredPercentage: _params[0],
            queuedVotePeriodLimit: _params[1],
            boostedVotePeriodLimit: _params[2],
            preBoostedVotePeriodLimit: _params[3],
            thresholdConst:uint216(_params[4]).fraction(uint216(1000)),
            limitExponentValue:limitExponent,
            quietEndingPeriod: _params[5],
            proposingRepReward: _params[6],
            votersReputationLossRatio:_params[7],
            minimumDaoBounty:_params[8],
            daoBountyConst:_params[9],
            activationTime:_params[10],
            voteOnBehalf:_voteOnBehalf
        });
        return paramsHash;
    }

    function redeem(bytes32 _proposalId, address _beneficiary) public returns (uint[3] memory rewards) {

        Proposal storage proposal = proposals[_proposalId];
        require((proposal.state == ProposalState.Executed)||(proposal.state == ProposalState.ExpiredInQueue),
        "Proposal should be Executed or ExpiredInQueue");
        Parameters memory params = parameters[proposal.paramsHash];
        uint256 lostReputation;
        if (proposal.winningVote == YES) {
            lostReputation = proposal.preBoostedVotes[NO];
        } else {
            lostReputation = proposal.preBoostedVotes[YES];
        }
        lostReputation = (lostReputation.mul(params.votersReputationLossRatio))/100;
        Staker storage staker = proposal.stakers[_beneficiary];
        uint256 totalStakes = proposal.stakes[NO].add(proposal.stakes[YES]);
        uint256 totalWinningStakes = proposal.stakes[proposal.winningVote];

        if (staker.amount > 0) {
            uint256 totalStakesLeftAfterCallBounty =
            totalStakes.sub(proposal.expirationCallBountyPercentage.mul(proposal.stakes[YES]).div(100));
            if (proposal.state == ProposalState.ExpiredInQueue) {
                rewards[0] = staker.amount;
            } else if (staker.vote == proposal.winningVote) {
                if (staker.vote == YES) {
                    if (proposal.daoBounty < totalStakesLeftAfterCallBounty) {
                        uint256 _totalStakes = totalStakesLeftAfterCallBounty.sub(proposal.daoBounty);
                        rewards[0] = (staker.amount.mul(_totalStakes))/totalWinningStakes;
                    }
                } else {
                    rewards[0] = (staker.amount.mul(totalStakesLeftAfterCallBounty))/totalWinningStakes;
                }
            }
            staker.amount = 0;
        }
        if (proposal.daoRedeemItsWinnings == false &&
            _beneficiary == organizations[proposal.organizationId] &&
            proposal.state != ProposalState.ExpiredInQueue &&
            proposal.winningVote == NO) {
            rewards[0] =
            rewards[0].add((proposal.daoBounty.mul(totalStakes))/totalWinningStakes).sub(proposal.daoBounty);
            proposal.daoRedeemItsWinnings = true;
        }

        Voter storage voter = proposal.voters[_beneficiary];
        if ((voter.reputation != 0) && (voter.preBoosted)) {
            if (proposal.state == ProposalState.ExpiredInQueue) {
                rewards[1] = ((voter.reputation.mul(params.votersReputationLossRatio))/100);
            } else if (proposal.winningVote == voter.vote) {
                rewards[1] = ((voter.reputation.mul(params.votersReputationLossRatio))/100)
                .add((voter.reputation.mul(lostReputation))/proposal.preBoostedVotes[proposal.winningVote]);
            }
            voter.reputation = 0;
        }
        if ((proposal.proposer == _beneficiary)&&(proposal.winningVote == YES)&&(proposal.proposer != address(0))) {
            rewards[2] = params.proposingRepReward;
            proposal.proposer = address(0);
        }
        if (rewards[0] != 0) {
            proposal.totalStakes = proposal.totalStakes.sub(rewards[0]);
            require(stakingToken.transfer(_beneficiary, rewards[0]), "transfer to beneficiary failed");
            emit Redeem(_proposalId, organizations[proposal.organizationId], _beneficiary, rewards[0]);
        }
        if (rewards[1].add(rewards[2]) != 0) {
            VotingMachineCallbacksInterface(proposal.callbacks)
            .mintReputation(rewards[1].add(rewards[2]), _beneficiary, _proposalId);
            emit RedeemReputation(
            _proposalId,
            organizations[proposal.organizationId],
            _beneficiary,
            rewards[1].add(rewards[2])
            );
        }
    }

    function redeemDaoBounty(bytes32 _proposalId, address _beneficiary)
    public
    returns(uint256 redeemedAmount, uint256 potentialAmount) {

        Proposal storage proposal = proposals[_proposalId];
        require(proposal.state == ProposalState.Executed);
        uint256 totalWinningStakes = proposal.stakes[proposal.winningVote];
        Staker storage staker = proposal.stakers[_beneficiary];
        if (
            (staker.amount4Bounty > 0)&&
            (staker.vote == proposal.winningVote)&&
            (proposal.winningVote == YES)&&
            (totalWinningStakes != 0)) {
                potentialAmount = (staker.amount4Bounty * proposal.daoBounty)/totalWinningStakes;
            }
        if ((potentialAmount != 0)&&
            (VotingMachineCallbacksInterface(proposal.callbacks)
            .balanceOfStakingToken(stakingToken, _proposalId) >= potentialAmount)) {
            staker.amount4Bounty = 0;
            proposal.daoBountyRemain = proposal.daoBountyRemain.sub(potentialAmount);
            require(
            VotingMachineCallbacksInterface(proposal.callbacks)
            .stakingTokenTransfer(stakingToken, _beneficiary, potentialAmount, _proposalId));
            redeemedAmount = potentialAmount;
            emit RedeemDaoBounty(_proposalId, organizations[proposal.organizationId], _beneficiary, redeemedAmount);
        }
    }

    function shouldBoost(bytes32 _proposalId) public view returns(bool) {

        Proposal memory proposal = proposals[_proposalId];
        return (_score(_proposalId) > threshold(proposal.paramsHash, proposal.organizationId));
    }

    function threshold(bytes32 _paramsHash, bytes32 _organizationId) public view returns(uint256) {

        uint256 power = orgBoostedProposalsCnt[_organizationId];
        Parameters storage params = parameters[_paramsHash];

        if (power > params.limitExponentValue) {
            power = params.limitExponentValue;
        }

        return params.thresholdConst.pow(power);
    }

    function getParametersHash(
        uint[11] memory _params,//use array here due to stack too deep issue.
        address _voteOnBehalf
    )
        public
        pure
        returns(bytes32)
        {

        return keccak256(
            abi.encodePacked(
            keccak256(
            abi.encodePacked(
                _params[0],
                _params[1],
                _params[2],
                _params[3],
                _params[4],
                _params[5],
                _params[6],
                _params[7],
                _params[8],
                _params[9],
                _params[10])
            ),
            _voteOnBehalf
        ));
    }

    function _execute(bytes32 _proposalId) internal votable(_proposalId) returns(bool) {

        Proposal storage proposal = proposals[_proposalId];
        Parameters memory params = parameters[proposal.paramsHash];
        Proposal memory tmpProposal = proposal;
        uint256 totalReputation =
        VotingMachineCallbacksInterface(proposal.callbacks).getTotalReputationSupply(_proposalId);
        uint256 executionBar = (totalReputation/100) * params.queuedVoteRequiredPercentage;
        ExecutionState executionState = ExecutionState.None;
        uint256 averageDownstakesOfBoosted;
        uint256 confidenceThreshold;

        if (proposal.votes[proposal.winningVote] > executionBar) {
            if (proposal.state == ProposalState.Queued) {
                executionState = ExecutionState.QueueBarCrossed;
            } else if (proposal.state == ProposalState.PreBoosted) {
                executionState = ExecutionState.PreBoostedBarCrossed;
            } else {
                executionState = ExecutionState.BoostedBarCrossed;
            }
            proposal.state = ProposalState.Executed;
        } else {
            if (proposal.state == ProposalState.Queued) {
                if ((now - proposal.times[0]) >= params.queuedVotePeriodLimit) {
                    proposal.state = ProposalState.ExpiredInQueue;
                    proposal.winningVote = NO;
                    executionState = ExecutionState.QueueTimeOut;
                } else {
                    confidenceThreshold = threshold(proposal.paramsHash, proposal.organizationId);
                    if (_score(_proposalId) > confidenceThreshold) {
                        proposal.state = ProposalState.PreBoosted;
                        proposal.times[2] = now;
                        proposal.confidenceThreshold = confidenceThreshold;
                    }
                }
            }

            if (proposal.state == ProposalState.PreBoosted) {
                confidenceThreshold = threshold(proposal.paramsHash, proposal.organizationId);
                if ((now - proposal.times[2]) >= params.preBoostedVotePeriodLimit) {
                    if (_score(_proposalId) > confidenceThreshold) {
                        if (orgBoostedProposalsCnt[proposal.organizationId] < MAX_BOOSTED_PROPOSALS) {
                            proposal.state = ProposalState.Boosted;
                            proposal.times[1] = now;
                            orgBoostedProposalsCnt[proposal.organizationId]++;
                            averageDownstakesOfBoosted = averagesDownstakesOfBoosted[proposal.organizationId];
                            averagesDownstakesOfBoosted[proposal.organizationId] =
                                uint256(int256(averageDownstakesOfBoosted) +
                                ((int256(proposal.stakes[NO])-int256(averageDownstakesOfBoosted))/
                                int256(orgBoostedProposalsCnt[proposal.organizationId])));
                        }
                    } else {
                        proposal.state = ProposalState.Queued;
                    }
                } else { //check the Confidence level is stable
                    uint256 proposalScore = _score(_proposalId);
                    if (proposalScore <= proposal.confidenceThreshold.min(confidenceThreshold)) {
                        proposal.state = ProposalState.Queued;
                    } else if (proposal.confidenceThreshold > proposalScore) {
                        proposal.confidenceThreshold = confidenceThreshold;
                        emit ConfidenceLevelChange(_proposalId, confidenceThreshold);
                    }
                }
            }
        }

        if ((proposal.state == ProposalState.Boosted) ||
            (proposal.state == ProposalState.QuietEndingPeriod)) {
            if ((now - proposal.times[1]) >= proposal.currentBoostedVotePeriodLimit) {
                proposal.state = ProposalState.Executed;
                executionState = ExecutionState.BoostedTimeOut;
            }
        }

        if (executionState != ExecutionState.None) {
            if ((executionState == ExecutionState.BoostedTimeOut) ||
                (executionState == ExecutionState.BoostedBarCrossed)) {
                orgBoostedProposalsCnt[tmpProposal.organizationId] =
                orgBoostedProposalsCnt[tmpProposal.organizationId].sub(1);
                uint256 boostedProposals = orgBoostedProposalsCnt[tmpProposal.organizationId];
                if (boostedProposals == 0) {
                    averagesDownstakesOfBoosted[proposal.organizationId] = 0;
                } else {
                    averageDownstakesOfBoosted = averagesDownstakesOfBoosted[proposal.organizationId];
                    averagesDownstakesOfBoosted[proposal.organizationId] =
                    (averageDownstakesOfBoosted.mul(boostedProposals+1).sub(proposal.stakes[NO]))/boostedProposals;
                }
            }
            emit ExecuteProposal(
            _proposalId,
            organizations[proposal.organizationId],
            proposal.winningVote,
            totalReputation
            );
            emit GPExecuteProposal(_proposalId, executionState);
            ProposalExecuteInterface(proposal.callbacks).executeProposal(_proposalId, int(proposal.winningVote));
            proposal.daoBounty = proposal.daoBountyRemain;
        }
        if (tmpProposal.state != proposal.state) {
            emit StateChange(_proposalId, proposal.state);
        }
        return (executionState != ExecutionState.None);
    }

    function _stake(bytes32 _proposalId, uint256 _vote, uint256 _amount, address _staker) internal returns(bool) {

        require(_vote <= NUM_OF_CHOICES && _vote > 0, "wrong vote value");
        require(_amount > 0, "staking amount should be >0");

        if (_execute(_proposalId)) {
            return true;
        }
        Proposal storage proposal = proposals[_proposalId];

        if ((proposal.state != ProposalState.PreBoosted) &&
            (proposal.state != ProposalState.Queued)) {
            return false;
        }

        Staker storage staker = proposal.stakers[_staker];
        if ((staker.amount > 0) && (staker.vote != _vote)) {
            return false;
        }

        uint256 amount = _amount;
        require(stakingToken.transferFrom(_staker, address(this), amount), "fail transfer from staker");
        proposal.totalStakes = proposal.totalStakes.add(amount); //update totalRedeemableStakes
        staker.amount = staker.amount.add(amount);
        require(staker.amount <= 0x100000000000000000000000000000000, "staking amount is too high");
        require(proposal.totalStakes <= 0x100000000000000000000000000000000, "total stakes is too high");

        if (_vote == YES) {
            staker.amount4Bounty = staker.amount4Bounty.add(amount);
        }
        staker.vote = _vote;

        proposal.stakes[_vote] = amount.add(proposal.stakes[_vote]);
        emit Stake(_proposalId, organizations[proposal.organizationId], _staker, _vote, _amount);
        return _execute(_proposalId);
    }

    function internalVote(bytes32 _proposalId, address _voter, uint256 _vote, uint256 _rep) internal returns(bool) {

        require(_vote <= NUM_OF_CHOICES && _vote > 0, "0 < _vote <= 2");
        if (_execute(_proposalId)) {
            return true;
        }

        Parameters memory params = parameters[proposals[_proposalId].paramsHash];
        Proposal storage proposal = proposals[_proposalId];

        uint256 reputation = VotingMachineCallbacksInterface(proposal.callbacks).reputationOf(_voter, _proposalId);
        require(reputation > 0, "_voter must have reputation");
        require(reputation >= _rep, "reputation >= _rep");
        uint256 rep = _rep;
        if (rep == 0) {
            rep = reputation;
        }
        if (proposal.voters[_voter].reputation != 0) {
            return false;
        }
        proposal.votes[_vote] = rep.add(proposal.votes[_vote]);
        if ((proposal.votes[_vote] > proposal.votes[proposal.winningVote]) ||
            ((proposal.votes[NO] == proposal.votes[proposal.winningVote]) &&
            proposal.winningVote == YES)) {
            if (proposal.state == ProposalState.Boosted &&
                ((now - proposal.times[1]) >= (params.boostedVotePeriodLimit - params.quietEndingPeriod))||
                proposal.state == ProposalState.QuietEndingPeriod) {
                if (proposal.state != ProposalState.QuietEndingPeriod) {
                    proposal.currentBoostedVotePeriodLimit = params.quietEndingPeriod;
                    proposal.state = ProposalState.QuietEndingPeriod;
                }
                proposal.times[1] = now;
            }
            proposal.winningVote = _vote;
        }
        proposal.voters[_voter] = Voter({
            reputation: rep,
            vote: _vote,
            preBoosted:((proposal.state == ProposalState.PreBoosted) || (proposal.state == ProposalState.Queued))
        });
        if ((proposal.state == ProposalState.PreBoosted) || (proposal.state == ProposalState.Queued)) {
            proposal.preBoostedVotes[_vote] = rep.add(proposal.preBoostedVotes[_vote]);
            uint256 reputationDeposit = (params.votersReputationLossRatio.mul(rep))/100;
            VotingMachineCallbacksInterface(proposal.callbacks).burnReputation(reputationDeposit, _voter, _proposalId);
        }
        emit VoteProposal(_proposalId, organizations[proposal.organizationId], _voter, _vote, rep);
        return _execute(_proposalId);
    }

    function _score(bytes32 _proposalId) internal view returns(uint256) {

        Proposal storage proposal = proposals[_proposalId];
        return uint216(proposal.stakes[YES]).fraction(uint216(proposal.stakes[NO]));
    }

    function _isVotable(bytes32 _proposalId) internal view returns(bool) {

        ProposalState pState = proposals[_proposalId].state;
        return ((pState == ProposalState.PreBoosted)||
                (pState == ProposalState.Boosted)||
                (pState == ProposalState.QuietEndingPeriod)||
                (pState == ProposalState.Queued)
        );
    }
}


pragma solidity ^0.5.4;




contract GenesisProtocol is IntVoteInterface, GenesisProtocolLogic {

    using ECDSA for bytes32;

    bytes32 public constant DELEGATION_HASH_EIP712 =
    keccak256(abi.encodePacked(
    "address GenesisProtocolAddress",
    "bytes32 ProposalId",
    "uint256 Vote",
    "uint256 AmountToStake",
    "uint256 Nonce"
    ));

    mapping(address=>uint256) public stakesNonce; //stakes Nonce

    constructor(IERC20 _stakingToken)
    public
    GenesisProtocolLogic(_stakingToken) {
    }

    function stake(bytes32 _proposalId, uint256 _vote, uint256 _amount) external returns(bool) {

        return _stake(_proposalId, _vote, _amount, msg.sender);
    }

    function stakeWithSignature(
        bytes32 _proposalId,
        uint256 _vote,
        uint256 _amount,
        uint256 _nonce,
        uint256 _signatureType,
        bytes calldata _signature
        )
        external
        returns(bool)
        {

        bytes32 delegationDigest;
        if (_signatureType == 2) {
            delegationDigest = keccak256(
                abi.encodePacked(
                    DELEGATION_HASH_EIP712, keccak256(
                        abi.encodePacked(
                        address(this),
                        _proposalId,
                        _vote,
                        _amount,
                        _nonce)
                    )
                )
            );
        } else {
            delegationDigest = keccak256(
                        abi.encodePacked(
                        address(this),
                        _proposalId,
                        _vote,
                        _amount,
                        _nonce)
                    ).toEthSignedMessageHash();
        }
        address staker = delegationDigest.recover(_signature);
        require(staker != address(0), "staker address cannot be 0");
        require(stakesNonce[staker] == _nonce);
        stakesNonce[staker] = stakesNonce[staker].add(1);
        return _stake(_proposalId, _vote, _amount, staker);
    }

    function vote(bytes32 _proposalId, uint256 _vote, uint256 _amount, address _voter)
    external
    votable(_proposalId)
    returns(bool) {

        Proposal storage proposal = proposals[_proposalId];
        Parameters memory params = parameters[proposal.paramsHash];
        address voter;
        if (params.voteOnBehalf != address(0)) {
            require(msg.sender == params.voteOnBehalf);
            voter = _voter;
        } else {
            voter = msg.sender;
        }
        return internalVote(_proposalId, voter, _vote, _amount);
    }

    function cancelVote(bytes32 _proposalId) external votable(_proposalId) {

        return;
    }

    function execute(bytes32 _proposalId) external votable(_proposalId) returns(bool) {

        return _execute(_proposalId);
    }

    function getNumberOfChoices(bytes32) external view returns(uint256) {

        return NUM_OF_CHOICES;
    }

    function getProposalTimes(bytes32 _proposalId) external view returns(uint[3] memory times) {

        return proposals[_proposalId].times;
    }

    function voteInfo(bytes32 _proposalId, address _voter) external view returns(uint, uint) {

        Voter memory voter = proposals[_proposalId].voters[_voter];
        return (voter.vote, voter.reputation);
    }

    function voteStatus(bytes32 _proposalId, uint256 _choice) external view returns(uint256) {

        return proposals[_proposalId].votes[_choice];
    }

    function isVotable(bytes32 _proposalId) external view returns(bool) {

        return _isVotable(_proposalId);
    }

    function proposalStatus(bytes32 _proposalId) external view returns(uint256, uint256, uint256, uint256) {

        return (
                proposals[_proposalId].preBoostedVotes[YES],
                proposals[_proposalId].preBoostedVotes[NO],
                proposals[_proposalId].stakes[YES],
                proposals[_proposalId].stakes[NO]
        );
    }

    function getProposalOrganization(bytes32 _proposalId) external view returns(bytes32) {

        return (proposals[_proposalId].organizationId);
    }

    function getStaker(bytes32 _proposalId, address _staker) external view returns(uint256, uint256) {

        return (proposals[_proposalId].stakers[_staker].vote, proposals[_proposalId].stakers[_staker].amount);
    }

    function voteStake(bytes32 _proposalId, uint256 _vote) external view returns(uint256) {

        return proposals[_proposalId].stakes[_vote];
    }

    function winningVote(bytes32 _proposalId) external view returns(uint256) {

        return proposals[_proposalId].winningVote;
    }

    function state(bytes32 _proposalId) external view returns(ProposalState) {

        return proposals[_proposalId].state;
    }

    function isAbstainAllow() external pure returns(bool) {

        return false;
    }

    function getAllowedRangeOfChoices() external pure returns(uint256 min, uint256 max) {

        return (YES, NO);
    }

    function score(bytes32 _proposalId) public view returns(uint256) {

        return  _score(_proposalId);
    }
}


pragma solidity ^0.5.4;




contract VotingMachineCallbacks is VotingMachineCallbacksInterface {


    struct ProposalInfo {
        uint256 blockNumber; // the proposal's block number
        Avatar avatar; // the proposal's avatar
    }

    modifier onlyVotingMachine(bytes32 _proposalId) {

        require(proposalsInfo[msg.sender][_proposalId].avatar != Avatar(address(0)), "only VotingMachine");
        _;
    }

    mapping(address => mapping(bytes32 => ProposalInfo)) public proposalsInfo;

    function mintReputation(uint256 _amount, address _beneficiary, bytes32 _proposalId)
    external
    onlyVotingMachine(_proposalId)
    returns(bool)
    {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        if (avatar == Avatar(0)) {
            return false;
        }
        return ControllerInterface(avatar.owner()).mintReputation(_amount, _beneficiary, address(avatar));
    }

    function burnReputation(uint256 _amount, address _beneficiary, bytes32 _proposalId)
    external
    onlyVotingMachine(_proposalId)
    returns(bool)
    {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        if (avatar == Avatar(0)) {
            return false;
        }
        return ControllerInterface(avatar.owner()).burnReputation(_amount, _beneficiary, address(avatar));
    }

    function stakingTokenTransfer(
        IERC20 _stakingToken,
        address _beneficiary,
        uint256 _amount,
        bytes32 _proposalId)
    external
    onlyVotingMachine(_proposalId)
    returns(bool)
    {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        if (avatar == Avatar(0)) {
            return false;
        }
        return ControllerInterface(avatar.owner()).externalTokenTransfer(_stakingToken, _beneficiary, _amount, avatar);
    }

    function balanceOfStakingToken(IERC20 _stakingToken, bytes32 _proposalId) external view returns(uint256) {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        if (proposalsInfo[msg.sender][_proposalId].avatar == Avatar(0)) {
            return 0;
        }
        return _stakingToken.balanceOf(address(avatar));
    }

    function getTotalReputationSupply(bytes32 _proposalId) external view returns(uint256) {

        ProposalInfo memory proposal = proposalsInfo[msg.sender][_proposalId];
        if (proposal.avatar == Avatar(0)) {
            return 0;
        }
        return proposal.avatar.nativeReputation().totalSupplyAt(proposal.blockNumber);
    }

    function reputationOf(address _owner, bytes32 _proposalId) external view returns(uint256) {

        ProposalInfo memory proposal = proposalsInfo[msg.sender][_proposalId];
        if (proposal.avatar == Avatar(0)) {
            return 0;
        }
        return proposal.avatar.nativeReputation().balanceOfAt(_owner, proposal.blockNumber);
    }
}


pragma solidity ^0.5.4;







contract SchemeRegistrar is UniversalScheme, VotingMachineCallbacks, ProposalExecuteInterface {

    event NewSchemeProposal(
        address indexed _avatar,
        bytes32 indexed _proposalId,
        address indexed _intVoteInterface,
        address _scheme,
        bytes32 _parametersHash,
        bytes4 _permissions,
        string _descriptionHash
    );

    event RemoveSchemeProposal(address indexed _avatar,
        bytes32 indexed _proposalId,
        address indexed _intVoteInterface,
        address _scheme,
        string _descriptionHash
    );

    event ProposalExecuted(address indexed _avatar, bytes32 indexed _proposalId, int256 _param);
    event ProposalDeleted(address indexed _avatar, bytes32 indexed _proposalId);

    struct SchemeProposal {
        address scheme; //
        bool addScheme; // true: add a scheme, false: remove a scheme.
        bytes32 parametersHash;
        bytes4 permissions;
    }

    mapping(address=>mapping(bytes32=>SchemeProposal)) public organizationsProposals;

    struct Parameters {
        bytes32 voteRegisterParams;
        bytes32 voteRemoveParams;
        IntVoteInterface intVote;
    }

    mapping(bytes32=>Parameters) public parameters;

    function executeProposal(bytes32 _proposalId, int256 _param) external onlyVotingMachine(_proposalId) returns(bool) {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        SchemeProposal memory proposal = organizationsProposals[address(avatar)][_proposalId];
        require(proposal.scheme != address(0));
        delete organizationsProposals[address(avatar)][_proposalId];
        emit ProposalDeleted(address(avatar), _proposalId);
        if (_param == 1) {

            ControllerInterface controller = ControllerInterface(avatar.owner());

            if (proposal.addScheme) {
                require(controller.registerScheme(
                        proposal.scheme,
                        proposal.parametersHash,
                        proposal.permissions,
                        address(avatar))
                );
            }
            if (!proposal.addScheme) {
                require(controller.unregisterScheme(proposal.scheme, address(avatar)));
            }
        }
        emit ProposalExecuted(address(avatar), _proposalId, _param);
        return true;
    }

    function setParameters(
        bytes32 _voteRegisterParams,
        bytes32 _voteRemoveParams,
        IntVoteInterface _intVote
    ) public returns(bytes32)
    {

        bytes32 paramsHash = getParametersHash(_voteRegisterParams, _voteRemoveParams, _intVote);
        parameters[paramsHash].voteRegisterParams = _voteRegisterParams;
        parameters[paramsHash].voteRemoveParams = _voteRemoveParams;
        parameters[paramsHash].intVote = _intVote;
        return paramsHash;
    }

    function getParametersHash(
        bytes32 _voteRegisterParams,
        bytes32 _voteRemoveParams,
        IntVoteInterface _intVote
    ) public pure returns(bytes32)
    {

        return keccak256(abi.encodePacked(_voteRegisterParams, _voteRemoveParams, _intVote));
    }

    function proposeScheme(
        Avatar _avatar,
        address _scheme,
        bytes32 _parametersHash,
        bytes4 _permissions,
        string memory _descriptionHash
    )
    public
    returns(bytes32)
    {

        require(_scheme != address(0), "scheme cannot be zero");
        Parameters memory controllerParams = parameters[getParametersFromController(_avatar)];

        bytes32 proposalId = controllerParams.intVote.propose(
            2,
            controllerParams.voteRegisterParams,
            msg.sender,
            address(_avatar)
        );

        SchemeProposal memory proposal = SchemeProposal({
            scheme: _scheme,
            parametersHash: _parametersHash,
            addScheme: true,
            permissions: _permissions
        });
        emit NewSchemeProposal(
            address(_avatar),
            proposalId,
            address(controllerParams.intVote),
            _scheme, _parametersHash,
            _permissions,
            _descriptionHash
        );
        organizationsProposals[address(_avatar)][proposalId] = proposal;
        proposalsInfo[address(controllerParams.intVote)][proposalId] = ProposalInfo({
            blockNumber:block.number,
            avatar:_avatar
        });
        return proposalId;
    }

    function proposeToRemoveScheme(Avatar _avatar, address _scheme, string memory _descriptionHash)
    public
    returns(bytes32)
    {

        require(_scheme != address(0), "scheme cannot be zero");
        bytes32 paramsHash = getParametersFromController(_avatar);
        Parameters memory params = parameters[paramsHash];

        IntVoteInterface intVote = params.intVote;
        bytes32 proposalId = intVote.propose(2, params.voteRemoveParams, msg.sender, address(_avatar));
        organizationsProposals[address(_avatar)][proposalId].scheme = _scheme;
        emit RemoveSchemeProposal(address(_avatar), proposalId, address(intVote), _scheme, _descriptionHash);
        proposalsInfo[address(params.intVote)][proposalId] = ProposalInfo({
            blockNumber:block.number,
            avatar:_avatar
        });
        return proposalId;
    }
}


pragma solidity ^0.5.4;







contract UpgradeScheme is UniversalScheme, VotingMachineCallbacks, ProposalExecuteInterface {


    event NewUpgradeProposal(
        address indexed _avatar,
        bytes32 indexed _proposalId,
        address indexed _intVoteInterface,
        address _newController,
        string _descriptionHash
    );

    event ChangeUpgradeSchemeProposal(
        address indexed _avatar,
        bytes32 indexed _proposalId,
        address indexed _intVoteInterface,
        address _newUpgradeScheme,
        bytes32 _params,
        string _descriptionHash
    );

    event ProposalExecuted(address indexed _avatar, bytes32 indexed _proposalId, int256 _param);
    event ProposalDeleted(address indexed _avatar, bytes32 indexed _proposalId);

    struct UpgradeProposal {
        address upgradeContract; // Either the new controller we upgrade to, or the new upgrading scheme.
        bytes32 params; // Params for the new upgrading scheme.
        uint256 proposalType; // 1: Upgrade controller, 2: change upgrade scheme.
    }

    mapping(address=>mapping(bytes32=>UpgradeProposal)) public organizationsProposals;

    struct Parameters {
        bytes32 voteParams;
        IntVoteInterface intVote;
    }

    mapping(bytes32=>Parameters) public parameters;

    function executeProposal(bytes32 _proposalId, int256 _param) external onlyVotingMachine(_proposalId) returns(bool) {

        Avatar avatar = proposalsInfo[msg.sender][_proposalId].avatar;
        UpgradeProposal memory proposal = organizationsProposals[address(avatar)][_proposalId];
        require(proposal.proposalType != 0);
        delete organizationsProposals[address(avatar)][_proposalId];
        emit ProposalDeleted(address(avatar), _proposalId);
        if (_param == 1) {

            ControllerInterface controller = ControllerInterface(avatar.owner());
            if (proposal.proposalType == 1) {
                require(controller.upgradeController(proposal.upgradeContract, avatar));
            }

            if (proposal.proposalType == 2) {
                bytes4 permissions = controller.getSchemePermissions(address(this), address(avatar));
                require(
                controller.registerScheme(proposal.upgradeContract, proposal.params, permissions, address(avatar))
                );
                if (proposal.upgradeContract != address(this)) {
                    require(controller.unregisterSelf(address(avatar)));
                }
            }
        }
        emit ProposalExecuted(address(avatar), _proposalId, _param);
        return true;
    }

    function setParameters(
        bytes32 _voteParams,
        IntVoteInterface _intVote
    ) public returns(bytes32)
    {

        bytes32 paramsHash = getParametersHash(_voteParams, _intVote);
        parameters[paramsHash].voteParams = _voteParams;
        parameters[paramsHash].intVote = _intVote;
        return paramsHash;
    }

    function getParametersHash(
        bytes32 _voteParams,
        IntVoteInterface _intVote
    ) public pure returns(bytes32)
    {

        return  (keccak256(abi.encodePacked(_voteParams, _intVote)));
    }

    function proposeUpgrade(Avatar _avatar, address _newController, string memory _descriptionHash)
        public
        returns(bytes32)
    {

        Parameters memory params = parameters[getParametersFromController(_avatar)];
        bytes32 proposalId = params.intVote.propose(2, params.voteParams, msg.sender, address(_avatar));
        UpgradeProposal memory proposal = UpgradeProposal({
            proposalType: 1,
            upgradeContract: _newController,
            params: bytes32(0)
        });
        organizationsProposals[address(_avatar)][proposalId] = proposal;
        emit NewUpgradeProposal(
        address(_avatar),
        proposalId,
        address(params.intVote),
        _newController,
        _descriptionHash
        );
        proposalsInfo[address(params.intVote)][proposalId] = ProposalInfo({
            blockNumber:block.number,
            avatar:_avatar
        });
        return proposalId;
    }

    function proposeChangeUpgradingScheme(
        Avatar _avatar,
        address _scheme,
        bytes32 _params,
        string memory _descriptionHash
    )
        public
        returns(bytes32)
    {

        Parameters memory params = parameters[getParametersFromController(_avatar)];
        IntVoteInterface intVote = params.intVote;
        bytes32 proposalId = intVote.propose(2, params.voteParams, msg.sender, address(_avatar));
        require(organizationsProposals[address(_avatar)][proposalId].proposalType == 0);

        UpgradeProposal memory proposal = UpgradeProposal({
            proposalType: 2,
            upgradeContract: _scheme,
            params: _params
        });
        organizationsProposals[address(_avatar)][proposalId] = proposal;

        emit ChangeUpgradeSchemeProposal(
            address(_avatar),
            proposalId,
            address(params.intVote),
            _scheme,
            _params,
            _descriptionHash
        );
        proposalsInfo[address(intVote)][proposalId] = ProposalInfo({
            blockNumber:block.number,
            avatar:_avatar
        });
        return proposalId;
    }
}


pragma solidity ^0.5.4;







contract AbsoluteVote is IntVoteInterface {

    using SafeMath for uint;

    struct Parameters {
        uint256 precReq; // how many percentages required for the proposal to be passed
        address voteOnBehalf; //if this address is set so only this address is allowed
    }

    struct Voter {
        uint256 vote; // 0 - 'abstain'
        uint256 reputation; // amount of voter's reputation
    }

    struct Proposal {
        bytes32 organizationId; // the organization Id
        bool open; // voting open flag
        address callbacks;
        uint256 numOfChoices;
        bytes32 paramsHash; // the hash of the parameters of the proposal
        uint256 totalVotes;
        mapping(uint=>uint) votes;
        mapping(address=>Voter) voters;
    }

    event AVVoteProposal(bytes32 indexed _proposalId, bool _isProxyVote);

    mapping(bytes32=>Parameters) public parameters;  // A mapping from hashes to parameters
    mapping(bytes32=>Proposal) public proposals; // Mapping from the ID of the proposal to the proposal itself.
    mapping(bytes32=>address) public organizations;

    uint256 public constant MAX_NUM_OF_CHOICES = 10;
    uint256 public proposalsCnt; // Total amount of proposals

    modifier votable(bytes32 _proposalId) {

        require(proposals[_proposalId].open);
        _;
    }

    function propose(uint256 _numOfChoices, bytes32 _paramsHash, address, address _organization)
        external
        returns(bytes32)
    {

        require(parameters[_paramsHash].precReq > 0);
        require(_numOfChoices > 0 && _numOfChoices <= MAX_NUM_OF_CHOICES);
        bytes32 proposalId = keccak256(abi.encodePacked(this, proposalsCnt));
        proposalsCnt = proposalsCnt.add(1);
        Proposal memory proposal;
        proposal.numOfChoices = _numOfChoices;
        proposal.paramsHash = _paramsHash;
        proposal.callbacks = msg.sender;
        proposal.organizationId = keccak256(abi.encodePacked(msg.sender, _organization));
        proposal.open = true;
        proposals[proposalId] = proposal;
        if (organizations[proposal.organizationId] == address(0)) {
            if (_organization == address(0)) {
                organizations[proposal.organizationId] = msg.sender;
            } else {
                organizations[proposal.organizationId] = _organization;
            }
        }
        emit NewProposal(proposalId, organizations[proposal.organizationId], _numOfChoices, msg.sender, _paramsHash);
        return proposalId;
    }

    function vote(
        bytes32 _proposalId,
        uint256 _vote,
        uint256 _amount,
        address _voter)
        external
        votable(_proposalId)
        returns(bool)
        {


        Proposal storage proposal = proposals[_proposalId];
        Parameters memory params = parameters[proposal.paramsHash];
        address voter;
        if (params.voteOnBehalf != address(0)) {
            require(msg.sender == params.voteOnBehalf);
            voter = _voter;
        } else {
            voter = msg.sender;
        }
        return internalVote(_proposalId, voter, _vote, _amount);
    }

    function cancelVote(bytes32 _proposalId) external votable(_proposalId) {

        cancelVoteInternal(_proposalId, msg.sender);
    }

    function execute(bytes32 _proposalId) external votable(_proposalId) returns(bool) {

        return _execute(_proposalId);
    }

    function getNumberOfChoices(bytes32 _proposalId) external view returns(uint256) {

        return proposals[_proposalId].numOfChoices;
    }

    function voteInfo(bytes32 _proposalId, address _voter) external view returns(uint, uint) {

        Voter memory voter = proposals[_proposalId].voters[_voter];
        return (voter.vote, voter.reputation);
    }

    function voteStatus(bytes32 _proposalId, uint256 _choice) external view returns(uint256) {

        return proposals[_proposalId].votes[_choice];
    }

    function isVotable(bytes32 _proposalId) external view returns(bool) {

        return  proposals[_proposalId].open;
    }

    function isAbstainAllow() external pure returns(bool) {

        return true;
    }

    function getAllowedRangeOfChoices() external pure returns(uint256 min, uint256 max) {

        return (0, MAX_NUM_OF_CHOICES);
    }

    function setParameters(uint256 _precReq, address _voteOnBehalf) public returns(bytes32) {

        require(_precReq <= 100 && _precReq > 0);
        bytes32 hashedParameters = getParametersHash(_precReq, _voteOnBehalf);
        parameters[hashedParameters] = Parameters({
            precReq: _precReq,
            voteOnBehalf: _voteOnBehalf
        });
        return hashedParameters;
    }

    function getParametersHash(uint256 _precReq, address _voteOnBehalf) public pure returns(bytes32) {

        return keccak256(abi.encodePacked(_precReq, _voteOnBehalf));
    }

    function cancelVoteInternal(bytes32 _proposalId, address _voter) internal {

        Proposal storage proposal = proposals[_proposalId];
        Voter memory voter = proposal.voters[_voter];
        proposal.votes[voter.vote] = (proposal.votes[voter.vote]).sub(voter.reputation);
        proposal.totalVotes = (proposal.totalVotes).sub(voter.reputation);
        delete proposal.voters[_voter];
        emit CancelVoting(_proposalId, organizations[proposal.organizationId], _voter);
    }

    function deleteProposal(bytes32 _proposalId) internal {

        Proposal storage proposal = proposals[_proposalId];
        for (uint256 cnt = 0; cnt <= proposal.numOfChoices; cnt++) {
            delete proposal.votes[cnt];
        }
        delete proposals[_proposalId];
    }

    function _execute(bytes32 _proposalId) internal votable(_proposalId) returns(bool) {

        Proposal storage proposal = proposals[_proposalId];
        uint256 totalReputation =
        VotingMachineCallbacksInterface(proposal.callbacks).getTotalReputationSupply(_proposalId);
        uint256 precReq = parameters[proposal.paramsHash].precReq;
        for (uint256 cnt = 0; cnt <= proposal.numOfChoices; cnt++) {
            if (proposal.votes[cnt] > (totalReputation/100)*precReq) {
                Proposal memory tmpProposal = proposal;
                deleteProposal(_proposalId);
                emit ExecuteProposal(_proposalId, organizations[tmpProposal.organizationId], cnt, totalReputation);
                return ProposalExecuteInterface(tmpProposal.callbacks).executeProposal(_proposalId, int(cnt));
            }
        }
        return false;
    }

    function internalVote(bytes32 _proposalId, address _voter, uint256 _vote, uint256 _rep) internal returns(bool) {

        Proposal storage proposal = proposals[_proposalId];
        require(_vote <= proposal.numOfChoices);
        uint256 reputation = VotingMachineCallbacksInterface(proposal.callbacks).reputationOf(_voter, _proposalId);
        require(reputation > 0, "_voter must have reputation");
        require(reputation >= _rep);
        uint256 rep = _rep;
        if (rep == 0) {
            rep = reputation;
        }
        if (proposal.voters[_voter].reputation != 0) {
            cancelVoteInternal(_proposalId, _voter);
        }
        proposal.votes[_vote] = rep.add(proposal.votes[_vote]);
        proposal.totalVotes = rep.add(proposal.totalVotes);
        proposal.voters[_voter] = Voter({
            reputation: rep,
            vote: _vote
        });
        emit VoteProposal(_proposalId, organizations[proposal.organizationId], _voter, _vote, rep);
        emit AVVoteProposal(_proposalId, (_voter != msg.sender));
        return _execute(_proposalId);
    }
}


pragma solidity ^0.5.0;

library Roles {

    struct Role {
        mapping (address => bool) bearer;
    }

    function add(Role storage role, address account) internal {

        require(account != address(0));
        require(!has(role, account));

        role.bearer[account] = true;
    }

    function remove(Role storage role, address account) internal {

        require(account != address(0));
        require(has(role, account));

        role.bearer[account] = false;
    }

    function has(Role storage role, address account) internal view returns (bool) {

        require(account != address(0));
        return role.bearer[account];
    }
}


pragma solidity ^0.5.0;


contract PauserRole {

    using Roles for Roles.Role;

    event PauserAdded(address indexed account);
    event PauserRemoved(address indexed account);

    Roles.Role private _pausers;

    constructor () internal {
        _addPauser(msg.sender);
    }

    modifier onlyPauser() {

        require(isPauser(msg.sender));
        _;
    }

    function isPauser(address account) public view returns (bool) {

        return _pausers.has(account);
    }

    function addPauser(address account) public onlyPauser {

        _addPauser(account);
    }

    function renouncePauser() public {

        _removePauser(msg.sender);
    }

    function _addPauser(address account) internal {

        _pausers.add(account);
        emit PauserAdded(account);
    }

    function _removePauser(address account) internal {

        _pausers.remove(account);
        emit PauserRemoved(account);
    }
}


pragma solidity ^0.5.0;


contract Pausable is PauserRole {

    event Paused(address account);
    event Unpaused(address account);

    bool private _paused;

    constructor () internal {
        _paused = false;
    }

    function paused() public view returns (bool) {

        return _paused;
    }

    modifier whenNotPaused() {

        require(!_paused);
        _;
    }

    modifier whenPaused() {

        require(_paused);
        _;
    }

    function pause() public onlyPauser whenNotPaused {

        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() public onlyPauser whenPaused {

        _paused = false;
        emit Unpaused(msg.sender);
    }
}


pragma solidity >0.5.4;




contract SchemeGuard is Ownable {

    Avatar avatar;
    ControllerInterface internal controller = ControllerInterface(0);

    constructor(Avatar _avatar) public {
        avatar = _avatar;

        if (avatar != Avatar(0)) {
            controller = ControllerInterface(avatar.owner());
        }
    }

    modifier onlyAvatar() {

        require(address(avatar) == msg.sender, "only Avatar can call this method");
        _;
    }

    modifier onlyRegistered() {

        require(isRegistered(), "Scheme is not registered");
        _;
    }

    modifier onlyNotRegistered() {

        require(!isRegistered(), "Scheme is registered");
        _;
    }

    modifier onlyRegisteredCaller() {

        require(isRegistered(msg.sender), "Calling scheme is not registered");
        _;
    }

    function setAvatar(Avatar _avatar) public onlyOwner {

        avatar = _avatar;
        controller = ControllerInterface(avatar.owner());
    }

    function isRegistered() public view returns (bool) {

        return isRegistered(address(this));
    }

    function isRegistered(address scheme) public view returns (bool) {

        require(avatar != Avatar(0), "Avatar is not set");

        if (!(controller.isSchemeRegistered(scheme, address(avatar)))) {
            return false;
        }
        return true;
    }
}





contract IdentityAdminRole is Ownable {

    using Roles for Roles.Role;

    event IdentityAdminAdded(address indexed account);
    event IdentityAdminRemoved(address indexed account);

    Roles.Role private IdentityAdmins;

    constructor() internal {
        _addIdentityAdmin(msg.sender);
    }

    modifier onlyIdentityAdmin() {

        require(isIdentityAdmin(msg.sender), "not IdentityAdmin");
        _;
    }

    function isIdentityAdmin(address account) public view returns (bool) {

        return IdentityAdmins.has(account);
    }

    function addIdentityAdmin(address account) public onlyOwner returns (bool) {

        _addIdentityAdmin(account);
        return true;
    }

    function removeIdentityAdmin(address account) public onlyOwner returns (bool) {

        _removeIdentityAdmin(account);
        return true;
    }

    function renounceIdentityAdmin() public {

        _removeIdentityAdmin(msg.sender);
    }

    function _addIdentityAdmin(address account) internal {

        IdentityAdmins.add(account);
        emit IdentityAdminAdded(account);
    }

    function _removeIdentityAdmin(address account) internal {

        IdentityAdmins.remove(account);
        emit IdentityAdminRemoved(account);
    }
}









contract Identity is IdentityAdminRole, SchemeGuard, Pausable {

    using Roles for Roles.Role;
    using SafeMath for uint256;

    Roles.Role private blacklist;
    Roles.Role private whitelist;
    Roles.Role private contracts;

    uint256 public whitelistedCount = 0;
    uint256 public whitelistedContracts = 0;
    uint256 public authenticationPeriod = 14;

    mapping(address => uint256) public dateAuthenticated;
    mapping(address => uint256) public dateAdded;

    mapping(address => string) public addrToDID;
    mapping(bytes32 => address) public didHashToAddress;

    event BlacklistAdded(address indexed account);
    event BlacklistRemoved(address indexed account);

    event WhitelistedAdded(address indexed account);
    event WhitelistedRemoved(address indexed account);

    event ContractAdded(address indexed account);
    event ContractRemoved(address indexed account);

    constructor() public SchemeGuard(Avatar(0)) {}

    function setAuthenticationPeriod(uint256 period) public onlyOwner whenNotPaused {

        authenticationPeriod = period;
    }

    function authenticate(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        dateAuthenticated[account] = now;
    }

    function addWhitelisted(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        _addWhitelisted(account);
    }

    function addWhitelistedWithDID(address account, string memory did)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        _addWhitelistedWithDID(account, did);
    }

    function removeWhitelisted(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        _removeWhitelisted(account);
    }

    function renounceWhitelisted() public whenNotPaused {

        _removeWhitelisted(msg.sender);
    }

    function isWhitelisted(address account) public view returns (bool) {

        uint256 daysSinceAuthentication = (now.sub(dateAuthenticated[account])) / 1 days;
        return
            (daysSinceAuthentication <= authenticationPeriod) && whitelist.has(account);
    }

    function lastAuthenticated(address account) public view returns (uint256) {

        return dateAuthenticated[account];
    }





    function addBlacklisted(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        blacklist.add(account);
        emit BlacklistAdded(account);
    }

    function removeBlacklisted(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        blacklist.remove(account);
        emit BlacklistRemoved(account);
    }

    function addContract(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        require(isContract(account), "Given address is not a contract");
        contracts.add(account);
        _addWhitelisted(account);

        emit ContractAdded(account);
    }

    function removeContract(address account)
        public
        onlyRegistered
        onlyIdentityAdmin
        whenNotPaused
    {

        contracts.remove(account);
        _removeWhitelisted(account);

        emit ContractRemoved(account);
    }

    function isDAOContract(address account) public view returns (bool) {

        return contracts.has(account);
    }

    function _addWhitelisted(address account) internal {

        whitelist.add(account);

        whitelistedCount += 1;
        dateAdded[account] = now;
        dateAuthenticated[account] = now;

        if (isContract(account)) {
            whitelistedContracts += 1;
        }

        emit WhitelistedAdded(account);
    }

    function _addWhitelistedWithDID(address account, string memory did) internal {

        bytes32 pHash = keccak256(bytes(did));
        require(didHashToAddress[pHash] == address(0), "DID already registered");

        addrToDID[account] = did;
        didHashToAddress[pHash] = account;

        _addWhitelisted(account);
    }

    function _removeWhitelisted(address account) internal {

        whitelist.remove(account);

        whitelistedCount -= 1;
        delete dateAuthenticated[account];

        if (isContract(account)) {
            whitelistedContracts -= 1;
        }

        string memory did = addrToDID[account];
        bytes32 pHash = keccak256(bytes(did));

        delete dateAuthenticated[account];
        delete addrToDID[account];
        delete didHashToAddress[pHash];

        emit WhitelistedRemoved(account);
    }

    function isBlacklisted(address account) public view returns (bool) {

        return blacklist.has(account);
    }

    function isContract(address _addr) internal view returns (bool) {

        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}





contract IdentityGuard is Ownable {

    Identity public identity;

    constructor(Identity _identity) public {
        require(_identity != Identity(0), "Supplied identity is null");
        identity = _identity;
    }

    modifier onlyNotBlacklisted() {

        require(!identity.isBlacklisted(msg.sender), "Caller is blacklisted");
        _;
    }

    modifier requireNotBlacklisted(address _account) {

        require(!identity.isBlacklisted(_account), "Receiver is blacklisted");
        _;
    }

    modifier onlyWhitelisted() {

        require(identity.isWhitelisted(msg.sender), "is not whitelisted");
        _;
    }

    modifier requireWhitelisted(address _account) {

        require(identity.isWhitelisted(_account), "is not whitelisted");
        _;
    }

    modifier onlyDAOContract() {

        require(identity.isDAOContract(msg.sender), "is not whitelisted contract");
        _;
    }

    modifier requireDAOContract(address _contract) {

        require(identity.isDAOContract(_contract), "is not whitelisted contract");
        _;
    }

    modifier onlyAddedBefore(uint256 date) {

        require(
            identity.lastAuthenticated(msg.sender) <= date,
            "Was not added within period"
        );
        _;
    }

    modifier onlyIdentityAdmin() {

        require(identity.isIdentityAdmin(msg.sender), "not IdentityAdmin");
        _;
    }

    function setIdentity(Identity _identity) public onlyOwner {

        require(_identity.isRegistered(), "Identity is not registered");
        identity = _identity;
    }
}






contract AbstractFees is SchemeGuard {

    constructor() public SchemeGuard(Avatar(0)) {}

    function getTxFees(
        uint256 _value,
        address _sender,
        address _recipient
    ) public view returns (uint256, bool);

}

contract FeeFormula is AbstractFees {

    using SafeMath for uint256;

    uint256 public percentage;
    bool public constant senderPays = false;

    constructor(uint256 _percentage) public {
        require(_percentage < 100, "Percentage should be <100");
        percentage = _percentage;
    }

    function getTxFees(
        uint256 _value,
        address _sender,
        address _recipient
    ) public view returns (uint256, bool) {

        return (_value.mul(percentage).div(100), senderPays);
    }
}





contract FormulaHolder is Ownable {

    AbstractFees public formula;

    constructor(AbstractFees _formula) public {
        require(_formula != AbstractFees(0), "Supplied formula is null");
        formula = _formula;
    }

    function setFormula(AbstractFees _formula) public onlyOwner {

        _formula.isRegistered();
        formula = _formula;
    }
}



interface ERC677 {

    event Transfer(address indexed from, address indexed to, uint256 value, bytes data);

    function transferAndCall(
        address,
        uint256,
        bytes calldata
    ) external returns (bool);

}



interface ERC677Receiver {

    function onTokenTransfer(
        address _from,
        uint256 _value,
        bytes calldata _data
    ) external returns (bool);

}


pragma solidity ^0.5.0;



contract ERC20Pausable is ERC20, Pausable {

    function transfer(address to, uint256 value) public whenNotPaused returns (bool) {

        return super.transfer(to, value);
    }

    function transferFrom(address from, address to, uint256 value) public whenNotPaused returns (bool) {

        return super.transferFrom(from, to, value);
    }

    function approve(address spender, uint256 value) public whenNotPaused returns (bool) {

        return super.approve(spender, value);
    }

    function increaseAllowance(address spender, uint addedValue) public whenNotPaused returns (bool success) {

        return super.increaseAllowance(spender, addedValue);
    }

    function decreaseAllowance(address spender, uint subtractedValue) public whenNotPaused returns (bool success) {

        return super.decreaseAllowance(spender, subtractedValue);
    }
}







contract ERC677Token is ERC677, DAOToken, ERC20Pausable {

    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _cap
    ) public DAOToken(_name, _symbol, _cap) {}

    function _transferAndCall(
        address _to,
        uint256 _value,
        bytes memory _data
    ) internal whenNotPaused returns (bool) {

        bool res = super.transfer(_to, _value);
        emit Transfer(msg.sender, _to, _value, _data);

        if (isContract(_to)) {
            require(contractFallback(_to, _value, _data), "Contract fallback failed");
        }
        return res;
    }

    function contractFallback(
        address _to,
        uint256 _value,
        bytes memory _data
    ) private returns (bool) {

        ERC677Receiver receiver = ERC677Receiver(_to);
        require(
            receiver.onTokenTransfer(msg.sender, _value, _data),
            "Contract Fallback failed"
        );
        return true;
    }


    function isContract(address _addr) internal view returns (bool) {

        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}


pragma solidity ^0.5.0;


contract MinterRole {

    using Roles for Roles.Role;

    event MinterAdded(address indexed account);
    event MinterRemoved(address indexed account);

    Roles.Role private _minters;

    constructor () internal {
        _addMinter(msg.sender);
    }

    modifier onlyMinter() {

        require(isMinter(msg.sender));
        _;
    }

    function isMinter(address account) public view returns (bool) {

        return _minters.has(account);
    }

    function addMinter(address account) public onlyMinter {

        _addMinter(account);
    }

    function renounceMinter() public {

        _removeMinter(msg.sender);
    }

    function _addMinter(address account) internal {

        _minters.add(account);
        emit MinterAdded(account);
    }

    function _removeMinter(address account) internal {

        _minters.remove(account);
        emit MinterRemoved(account);
    }
}





contract ERC677BridgeToken is ERC677Token, MinterRole {

    address public bridgeContract;

    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _cap
    ) public ERC677Token(_name, _symbol, _cap) {}

    function setBridgeContract(address _bridgeContract) public onlyMinter {

        require(
            _bridgeContract != address(0) && isContract(_bridgeContract),
            "Invalid bridge contract"
        );
        bridgeContract = _bridgeContract;
    }
}






contract GoodDollar is ERC677BridgeToken, IdentityGuard, FormulaHolder {

    address feeRecipient;

    uint256 public constant decimals = 2;

    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _cap,
        AbstractFees _formula,
        Identity _identity,
        address _feeRecipient
    )
        public
        ERC677BridgeToken(_name, _symbol, _cap)
        IdentityGuard(_identity)
        FormulaHolder(_formula)
    {
        feeRecipient = _feeRecipient;
    }

    function transfer(address to, uint256 value) public returns (bool) {

        uint256 bruttoValue = processFees(msg.sender, to, value);
        return super.transfer(to, bruttoValue);
    }

    function approve(address spender, uint256 value) public returns (bool) {

        return super.approve(spender, value);
    }

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public returns (bool) {

        uint256 bruttoValue = processFees(from, to, value);
        return super.transferFrom(from, to, bruttoValue);
    }

    function transferAndCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external returns (bool) {

        uint256 bruttoValue = processFees(msg.sender, to, value);
        return super._transferAndCall(to, bruttoValue, data);
    }

    function mint(address to, uint256 value)
        public
        onlyMinter
        requireNotBlacklisted(to)
        returns (bool)
    {

        if (cap > 0) {
            require(totalSupply().add(value) <= cap, "Cannot increase supply beyond cap");
        }
        super._mint(to, value);
        return true;
    }

    function burn(uint256 value) public onlyNotBlacklisted {

        super.burn(value);
    }

    function burnFrom(address from, uint256 value)
        public
        onlyNotBlacklisted
        requireNotBlacklisted(from)
    {

        super.burnFrom(from, value);
    }

    function increaseAllowance(address spender, uint256 addedValue)
        public
        returns (bool)
    {

        return super.increaseAllowance(spender, addedValue);
    }

    function decreaseAllowance(address spender, uint256 subtractedValue)
        public
        returns (bool)
    {

        return super.decreaseAllowance(spender, subtractedValue);
    }

    function getFees(uint256 value) public view returns (uint256, bool) {

        return formula.getTxFees(value, address(0), address(0));
    }

    function getFees(
        uint256 value,
        address sender,
        address recipient
    ) public view returns (uint256, bool) {

        return formula.getTxFees(value, sender, recipient);
    }

    function setFeeRecipient(address _feeRecipient) public onlyOwner {

        feeRecipient = _feeRecipient;
    }

    function processFees(
        address account,
        address recipient,
        uint256 value
    ) internal returns (uint256) {

        (uint256 txFees, bool senderPays) = getFees(value, account, recipient);
        if (txFees > 0 && !identity.isDAOContract(msg.sender)) {
            require(
                senderPays == false || value.add(txFees) <= balanceOf(account),
                "Not enough balance to pay TX fee"
            );
            if (account == msg.sender) {
                super.transfer(feeRecipient, txFees);
            } else {
                super.transferFrom(account, feeRecipient, txFees);
            }

            return senderPays ? value : value.sub(txFees);
        }
        return value;
    }
}











contract ControllerCreatorGoodDollar {

    function create(Avatar _avatar, address _sender) public returns (address) {

        Controller controller = new Controller(_avatar);
        controller.registerScheme(
            _sender,
            bytes32(0),
            bytes4(0x0000001f),
            address(_avatar)
        );
        controller.unregisterScheme(address(this), address(_avatar));
        return address(controller);
    }
}

contract AddFoundersGoodDollar {

    ControllerCreatorGoodDollar private controllerCreatorGoodDollar;

    constructor(ControllerCreatorGoodDollar _controllerCreatorGoodDollar) public {
        controllerCreatorGoodDollar = _controllerCreatorGoodDollar;
    }

    function addFounders(
        GoodDollar nativeToken,
        Reputation nativeReputation,
        address _sender,
        address[] memory _founders,
        uint256 _avatarTokenAmount,
        uint256[] memory _foundersReputationAmount
    ) public returns (Avatar) {

        Avatar avatar = new Avatar("GoodDollar", nativeToken, nativeReputation);

        nativeToken.mint(address(avatar), _avatarTokenAmount);

        for (uint256 i = 0; i < _founders.length; i++) {
            require(_founders[i] != address(0), "Founder cannot be zero address");
            if (_foundersReputationAmount[i] > 0) {
                nativeReputation.mint(_founders[i], _foundersReputationAmount[i]);
            }
        }
        ControllerInterface controller = ControllerInterface(
            controllerCreatorGoodDollar.create(avatar, msg.sender)
        );

        nativeToken.setFeeRecipient(address(avatar));

        avatar.transferOwnership(address(controller));
        nativeToken.transferOwnership(address(avatar));
        nativeReputation.transferOwnership(address(controller));

        nativeToken.addMinter(_sender);
        nativeToken.addMinter(address(avatar));
        nativeToken.addMinter(address(controller));
        nativeToken.renounceMinter();
        return (avatar);
    }
}

contract DaoCreatorGoodDollar {

    Avatar public avatar;
    address public lock;

    event NewOrg(address _avatar);
    event InitialSchemesSet(address _avatar);

    AddFoundersGoodDollar private addFoundersGoodDollar;

    constructor(AddFoundersGoodDollar _addFoundersGoodDollar) public {
        addFoundersGoodDollar = _addFoundersGoodDollar;
    }

    function forgeOrg(
        string calldata _tokenName,
        string calldata _tokenSymbol,
        uint256 _cap,
        FeeFormula _formula,
        Identity _identity,
        address[] calldata _founders,
        uint256 _avatarTokenAmount,
        uint256[] calldata _foundersReputationAmount
    ) external returns (address) {

        return
            _forgeOrg(
                _tokenName,
                _tokenSymbol,
                _cap,
                _formula,
                _identity,
                _founders,
                _avatarTokenAmount,
                _foundersReputationAmount
            );
    }

    function setSchemes(
        Avatar _avatar,
        address[] calldata _schemes,
        bytes32[] calldata _params,
        bytes4[] calldata _permissions,
        string calldata _metaData
    ) external {

        require(lock == msg.sender, "Message sender is not lock");
        ControllerInterface controller = ControllerInterface(_avatar.owner());
        for (uint256 i = 0; i < _schemes.length; i++) {
            controller.registerScheme(
                _schemes[i],
                _params[i],
                _permissions[i],
                address(_avatar)
            );
        }
        controller.metaData(_metaData, _avatar);
        controller.unregisterScheme(address(this), address(_avatar));
        lock = address(0);
        emit InitialSchemesSet(address(_avatar));
    }

    function _forgeOrg(
        string memory _tokenName,
        string memory _tokenSymbol,
        uint256 _cap,
        FeeFormula _formula,
        Identity _identity,
        address[] memory _founders,
        uint256 _avatarTokenAmount,
        uint256[] memory _foundersReputationAmount
    ) private returns (address) {

        require(lock == address(0), "Lock already exists");
        require(
            _founders.length == _foundersReputationAmount.length,
            "Founder reputation missing"
        );
        require(_founders.length > 0, "Must have at least one founder");
        GoodDollar nativeToken = new GoodDollar(
            _tokenName,
            _tokenSymbol,
            _cap,
            _formula,
            _identity,
            address(0)
        );
        Reputation nativeReputation = new Reputation();

        nativeToken.addMinter(address(addFoundersGoodDollar));
        nativeToken.renounceMinter();

        nativeToken.transferOwnership(address(addFoundersGoodDollar));
        nativeReputation.transferOwnership(address(addFoundersGoodDollar));

        avatar = addFoundersGoodDollar.addFounders(
            nativeToken,
            nativeReputation,
            msg.sender,
            _founders,
            _avatarTokenAmount,
            _foundersReputationAmount
        );

        nativeToken.addPauser(address(avatar));

        lock = msg.sender;

        emit NewOrg(address(avatar));
        return (address(avatar));
    }
}