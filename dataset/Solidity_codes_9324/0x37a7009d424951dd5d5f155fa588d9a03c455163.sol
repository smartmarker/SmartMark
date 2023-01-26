
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

struct Provider {
    address addr;  //  if msg.sender == provider => self-Provider
    address module;  //  e.g. DSA Provider Module
}

struct Condition {
    address inst;  // can be AddressZero for self-conditional Actions
    bytes data;  // can be bytes32(0) for self-conditional Actions
}

enum Operation { Call, Delegatecall }

enum DataFlow { None, In, Out, InAndOut }

struct Action {
    address addr;
    bytes data;
    Operation operation;
    DataFlow dataFlow;
    uint256 value;
    bool termsOkCheck;
}

struct Task {
    Condition[] conditions;  // optional
    Action[] actions;
    uint256 selfProviderGasLimit;  // optional: 0 defaults to gelatoMaxGas
    uint256 selfProviderGasPriceCeil;  // optional: 0 defaults to NO_CEIL
}

struct TaskReceipt {
    uint256 id;
    address userProxy;
    Provider provider;
    uint256 index;
    Task[] tasks;
    uint256 expiryDate;
    uint256 cycleId;  // auto-filled by GelatoCore. 0 for non-cyclic/chained tasks
    uint256 submissionsLeft;
}

struct TaskSpec {
    address[] conditions;   // Address: optional AddressZero for self-conditional actions
    Action[] actions;
    uint256 gasPriceCeil;
}

interface IGelatoInterface {


    function submitTask(
        Provider calldata _provider,
        Task calldata _task,
        uint256 _expiryDate
    )
        external;



    function submitTaskCycle(
        Provider calldata _provider,
        Task[] calldata _tasks,
        uint256 _expiryDate,
        uint256 _cycles
    )
        external;



    function submitTaskChain(
        Provider calldata _provider,
        Task[] calldata _tasks,
        uint256 _expiryDate,
        uint256 _sumOfRequestedTaskSubmits
    )
        external;


    function multiCancelTasks(TaskReceipt[] calldata _taskReceipts) external;


    function multiProvide(
        address _executor,
        TaskSpec[] calldata _taskSpecs,
        address[] calldata _modules
    )
        external
        payable;



    function multiUnprovide(
        uint256 _withdrawAmount,
        TaskSpec[] calldata _taskSpecs,
        address[] calldata _modules
    )
        external;

}


interface MemoryInterface {

    function setUint(uint _id, uint _val) external;

    function getUint(uint _id) external returns (uint);

}

contract Helpers {


    function getMemoryAddr() internal pure returns (address) {

        return 0x8a5419CfC711B2343c17a6ABf4B2bAFaBb06957F; // InstaMemory Address
    }

    function setUint(uint setId, uint val) internal {

        if (setId != 0) MemoryInterface(getMemoryAddr()).setUint(setId, val);
    }

    function getUint(uint getId, uint val) internal returns (uint returnVal) {

        returnVal = getId == 0 ? val : MemoryInterface(getMemoryAddr()).getUint(getId);
    }

    function connectorID() public pure returns(uint _type, uint _id) {

        (_type, _id) = (1, 42);
    }
}

contract DSMath {


    function add(uint x, uint y) internal pure returns (uint z) {

        require((z = x + y) >= x, "math-not-safe");
    }

    function sub(uint x, uint y) internal pure returns (uint z) {

        require((z = x - y) <= x, "sub-overflow");
    }
}

contract GelatoHelpers is Helpers, DSMath {


    function getGelatoCoreAddr() internal pure returns (address) {

        return 0x1d681d76ce96E4d70a88A00EBbcfc1E47808d0b8; // Gelato Core address
    }

    function getInstadappProviderModuleAddr() internal pure returns (address) {

        return 0x0C25452d20cdFeEd2983fa9b9b9Cf4E81D6f2fE2; // ProviderModuleDSA Address
    }

}


contract GelatoResolver is GelatoHelpers {


    event LogMultiProvide(address indexed executor, TaskSpec[] indexed taskspecs, address[] indexed modules, uint256 ethToDeposit, uint256 getId, uint256 setId);

    event LogSubmitTask(Provider indexed provider, Task indexed task, uint256 indexed expiryDate, uint256 getId, uint256 setId);

    event LogSubmitTaskCycle(Provider indexed provider, Task[] indexed tasks, uint256 indexed expiryDate, uint256 getId, uint256 setId);

    event LogSubmitTaskChain(Provider indexed provider, Task[] indexed tasks, uint256 indexed expiryDate, uint256 getId, uint256 setId);

    event LogMultiUnprovide(TaskSpec[] indexed taskspecs, address[] indexed modules, uint256 ethToWithdraw, uint256 getId, uint256 setId);

    event LogMultiCancelTasks(TaskReceipt[] indexed taskReceipt, uint256 getId, uint256 setId);



    function multiProvide(
        address _executor,
        TaskSpec[] calldata _taskSpecs,
        address[] calldata _modules,
        uint256 _ethToDeposit,
        uint256 _getId,
        uint256 _setId
    )
        external
        payable
    {

        uint256 ethToDeposit = getUint(_getId, _ethToDeposit);
        ethToDeposit = ethToDeposit == uint(-1) ? address(this).balance : ethToDeposit;

        IGelatoInterface(getGelatoCoreAddr()).multiProvide.value(ethToDeposit)(
            _executor,
            _taskSpecs,
            _modules
        );

        setUint(_setId, ethToDeposit);

        emit LogMultiProvide(_executor, _taskSpecs, _modules, ethToDeposit, _getId, _setId);
    }

    function submitTask(
        Provider calldata _provider,
        Task calldata _task,
        uint256 _expiryDate
    )
        external
        payable
    {

        IGelatoInterface(getGelatoCoreAddr()).submitTask(_provider, _task, _expiryDate);

        emit LogSubmitTask(_provider, _task, _expiryDate, 0, 0);
    }

    function submitTaskCycle(
        Provider calldata _provider,
        Task[] calldata _tasks,
        uint256 _expiryDate,
        uint256 _cycles
    )
        external
        payable
    {

        IGelatoInterface(getGelatoCoreAddr()).submitTaskCycle(
            _provider,
            _tasks,
            _expiryDate,
            _cycles
        );

        emit LogSubmitTaskCycle(_provider, _tasks, _expiryDate, 0, 0);
    }

    function submitTaskChain(
        Provider calldata _provider,
        Task[] calldata _tasks,
        uint256 _expiryDate,
        uint256 _sumOfRequestedTaskSubmits
    )
        external
        payable
    {

        IGelatoInterface(getGelatoCoreAddr()).submitTaskChain(
            _provider,
            _tasks,
            _expiryDate,
            _sumOfRequestedTaskSubmits
        );

        emit LogSubmitTaskChain(_provider, _tasks, _expiryDate, 0, 0);
    }


    function multiUnprovide(
        uint256 _withdrawAmount,
        TaskSpec[] calldata _taskSpecs,
        address[] calldata _modules,
        uint256 _getId,
        uint256 _setId
    )
        external
        payable
    {

        uint256 withdrawAmount = getUint(_getId, _withdrawAmount);
        uint256 balanceBefore = address(this).balance;

        IGelatoInterface(getGelatoCoreAddr()).multiUnprovide(
            withdrawAmount,
            _taskSpecs,
            _modules
        );

        uint256 actualWithdrawAmount = sub(address(this).balance, balanceBefore);

        setUint(_setId, actualWithdrawAmount);

        emit LogMultiUnprovide(_taskSpecs, _modules, actualWithdrawAmount, _getId, _setId);
    }

    function multiCancelTasks(TaskReceipt[] calldata _taskReceipts)
        external
        payable
    {

        IGelatoInterface(getGelatoCoreAddr()).multiCancelTasks(_taskReceipts);

        emit LogMultiCancelTasks(_taskReceipts, 0, 0);
    }
}


contract ConnectGelato is GelatoResolver {

    string public name = "Gelato-v1.0";
}