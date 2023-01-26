
pragma solidity 0.6.6;

pragma experimental ABIEncoderV2;

interface IDocs {

    event DocsRegistered(address user, bytes32 hash, uint128 created);

    event DocsDeleted(address user, bytes32 hash);

    function registerDocs(bytes32 _hash) external returns(bool success);


    function deleteDocs(bytes32 _hash) external returns(bool success);


    function updateDocs(bytes32 _hash, bytes32 _newHash) external returns(bool success);


    function docInfo(address _user, bytes32 _hash) external view returns(bytes32 hash, uint256 created);


    function getDocs(address _user) external view returns(bytes32[] memory docs);


}


pragma solidity 0.6.6;

struct Document {
    bytes32 hash;
    uint128 createdAt;
}


pragma solidity 0.6.6;

interface IOwnable {

    event OwnershipTransferred(
        address indexed currentOwner,
        address indexed newOwner
    );

    function owner() external view returns (address ownerAddress);


    function transferOwnership(address newOwner) external returns (bool success);


    function renounceOwnership() external returns (bool success);

}


pragma solidity 0.6.6;


contract Ownable is IOwnable{

    address private _owner;

    event OwnershipTransferred(
        address indexed currentOwner,
        address indexed newOwner
    );

    constructor() internal {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {

        require(
            msg.sender == _owner,
            "Ownable : Function called by unauthorized user."
        );
        _;
    }

    function owner() external view override returns (address ownerAddress) {

        ownerAddress = _owner;
    }

    function transferOwnership(address newOwner)
        external
        override
        onlyOwner
        returns (bool success)
    {

        require(newOwner != address(0), "TransferOwnership/User renounceOwnership() for deleting owner");
        return _transferOwnership(newOwner);
    }

    function renounceOwnership() external override onlyOwner returns (bool success) {

        success = _transferOwnership(address(0));
    }

    function _transferOwnership(address newOwner) internal returns (bool success) {

        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
        success = true;
    }
}


pragma solidity 0.6.6;





contract Docs is IDocs, Ownable {


    mapping(bytes32 => Document) internal _docs;
    mapping(address => bytes32[]) internal _userDocs;

    function registerDocs(bytes32 _hash) external override returns(bool success) {

        require(_hash != bytes32(0), "Register/Invalid Hash");
        return _addDocs(msg.sender, _hash);
    }

    function deleteDocs(bytes32 _hash) external override returns(bool success) {

        return _deleteDocs(msg.sender, _hash);
    }

    function updateDocs(bytes32 _hash, bytes32 _newHash) external override returns(bool success){

        require(_newHash != bytes32(0), "Update/Invalid Hash");
        _deleteDocs(msg.sender, _hash);
        _addDocs(msg.sender, _newHash);
        return true;
    }

    function docInfo(address _user, bytes32 _hash) external override view returns(bytes32 hash, uint256 created) {

        bytes32 key = _getKey(_user, _hash);
        Document memory doc = _docs[key];
        hash = doc.hash;
        created = doc.createdAt;
    }

    function getDocs(address _user) external override view returns(bytes32[] memory docs){

        docs = _userDocs[_user];
    }

    function _addDocs(address _user, bytes32 _hash) internal returns(bool success) {

        bytes32 key = _getKey(_user, _hash);
        _userDocs[_user].push(_hash);
        Document storage doc = _docs[key];
        require(doc.hash == bytes32(0), "Register/Already Registered");
        doc.hash = _hash;
        doc.createdAt = uint128(now);
        emit DocsRegistered(_user, _hash, uint128(now));
        success = true;
    }

    function _deleteDocs(address _user, bytes32 _hash) internal returns(bool success){

        bytes32 key = _getKey(_user, _hash);
        uint256 index = _getIndex(_user, key);
        _userDocs[_user][index] = _userDocs[_user][_userDocs[_user].length-1];
        delete _docs[key];
        _userDocs[_user].pop();
        emit DocsDeleted(_user, _hash);
        return true;
    }

    function _getKey(address _user, bytes32 _hash) internal pure returns(bytes32) {

        return keccak256(abi.encodePacked(_user,_hash));
    }

    function _getIndex(address _user, bytes32 _docsId) internal view returns(uint256 index) {

        for(index = 0; index < _userDocs[_user].length; index++){
            if(_getKey(_user, _userDocs[_user][index]) == _docsId){
                return index;
            }
        }
        revert("Document not found!");
    }
}