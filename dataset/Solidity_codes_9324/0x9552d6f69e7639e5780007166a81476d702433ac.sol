

pragma solidity 0.6.11;
pragma experimental ABIEncoderV2;


interface KeeperLike {

    function checkUpkeep(bytes calldata checkData) external returns (bool upkeepNeeded, bytes memory performData);

    function performUpkeepSafe(bytes calldata performData) external;

    function performUpkeep(bytes calldata performData) external;    

}

contract BGelato {

    KeeperLike immutable public proxy;

    constructor(KeeperLike _proxy) public {
        proxy = _proxy;
    }

    function checker()
        external
        returns (bool canExec, bytes memory execPayload)
    {

        (bool upkeepNeeded, bytes memory performData) = proxy.checkUpkeep(bytes(""));
        canExec = upkeepNeeded;

        (uint qty, address bamm, uint bammBalance) = abi.decode(performData, (uint, address, uint));

        execPayload = abi.encodeWithSelector(
            BGelato.doer.selector,
            qty, bamm, bammBalance
        );
    }

    event Input(uint x, address y, uint z);
    event Input2(bytes d);
    function doer(uint qty, address bamm, uint bammBalance) external returns (bytes memory performData) {

        emit Input(qty, bamm, bammBalance);
        performData = abi.encode(qty, bamm, bammBalance);
        emit Input2(performData);
        proxy.performUpkeepSafe(performData);
    }

    function test(bytes calldata input) external {

        address(this).call(input);
    }
}