



pragma solidity ^0.8.0;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}




pragma solidity ^0.8.0;

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _setOwner(_msgSender());
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        _setOwner(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}



pragma solidity ^0.8.9;


contract Lib_AddressManager is Ownable {


    event AddressSet(string indexed _name, address _newAddress, address _oldAddress);


    mapping(bytes32 => address) private addresses;


    function setAddress(string memory _name, address _address) external onlyOwner {

        bytes32 nameHash = _getNameHash(_name);
        address oldAddress = addresses[nameHash];
        addresses[nameHash] = _address;

        emit AddressSet(_name, _address, oldAddress);
    }

    function getAddress(string memory _name) external view returns (address) {

        return addresses[_getNameHash(_name)];
    }


    function _getNameHash(string memory _name) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked(_name));
    }
}



pragma solidity ^0.8.9;


abstract contract Lib_AddressResolver {

    Lib_AddressManager public libAddressManager;


    constructor(address _libAddressManager) {
        libAddressManager = Lib_AddressManager(_libAddressManager);
    }


    function resolve(string memory _name) public view returns (address) {
        return libAddressManager.getAddress(_name);
    }
}



pragma solidity ^0.8.9;



interface iMVM_CanonicalTransaction {


    enum STAKESTATUS {
        INIT,
        SEQ_SET,
        VERIFIER_SET,
        PAYBACK
    }


    event VerifierStake(
        address _sender,
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        uint256 _amount
    );

    event SetBatchTxData(
        address _sender,
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        uint256 _stakeAmount,
        bool _verified,
        bool _sequencer
    );

    event AppendBatchElement (
        uint256 _chainId,
        uint256 _batchIndex,
        uint40 _shouldStartAtElement,
        uint24 _totalElementsToAppend,
        uint256 _txBatchSize,
        uint256 _txBatchTime,
        bytes32 _root
    );


    struct TxDataSlice {
        address sender;
        uint256 blockNumber;
        uint256 batchIndex;
        uint256 timestamp;
        bytes txData;
        bool verified;
    }

    struct TxDataRequestStake {
        address sender;
        uint256 blockNumber;
        uint256 batchIndex;
        uint256 timestamp;
        uint256 endtime;
        uint256 amount;
        STAKESTATUS status;
    }

    struct BatchElement {
        uint40 shouldStartAtElement;
        uint24 totalElementsToAppend;
        uint256 txBatchSize;
        uint256 txBatchTime; // sequencer client encode timestamp(ms)
        bytes32 root; // merkle hash root with [hash(txDataBytes + blockNumber)]
        uint256 timestamp; // block timestamp
    }




    function setStakeBaseCost(uint256 _stakeBaseCost) external;


    function getStakeBaseCost() external view returns (uint256);


    function setStakeUnitCost(uint256 _stakeUnitCost) external;


    function getStakeUnitCost() external view returns (uint256);


    function getStakeCostByBatch(uint256 _chainId, uint256 _batchIndex) external view returns (uint256);


    function setTxDataSliceSize(uint256 _size) external;


    function getTxDataSliceSize() external view returns (uint256);


    function setTxBatchSize(uint256 _size) external;


    function getTxBatchSize() external view returns (uint256);


    function setTxDataSliceCount(uint256 _count) external;


    function getTxDataSliceCount() external view returns (uint256);


    function setStakeSeqSeconds(uint256 _seconds) external;


    function getStakeSeqSeconds() external view returns (uint256);


    function isWhiteListed(address _verifier) external view returns(bool);


    function setWhiteList(address _verifier, bool _allowed) external;


    function disableWhiteList() external;


    function appendSequencerBatchByChainId() external;


    function setBatchTxDataForStake(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber, bytes memory _data, uint256 _leafIndex, uint256 _totalLeaves, bytes32[] memory _proof) external;


    function setBatchTxDataForVerifier(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber, bytes memory _data) external;


    function getBatchTxData(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber) external view returns (bytes memory txData, bool verified);


    function checkBatchTxHash(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber, bytes memory _data) external view returns (bytes32 txHash, bool verified);


    function setBatchTxDataVerified(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber, bool _verified) external;


    function verifierStake(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber) external payable;


    function withdrawStake(uint256 _chainId, uint256 _batchIndex, uint256 _blockNumber) external;


}



pragma solidity ^0.8.9;

library Lib_RLPReader {


    uint256 internal constant MAX_LIST_LENGTH = 32;


    enum RLPItemType {
        DATA_ITEM,
        LIST_ITEM
    }


    struct RLPItem {
        uint256 length;
        uint256 ptr;
    }


    function toRLPItem(bytes memory _in) internal pure returns (RLPItem memory) {

        uint256 ptr;
        assembly {
            ptr := add(_in, 32)
        }

        return RLPItem({ length: _in.length, ptr: ptr });
    }

    function readList(RLPItem memory _in) internal pure returns (RLPItem[] memory) {

        (uint256 listOffset, , RLPItemType itemType) = _decodeLength(_in);

        require(itemType == RLPItemType.LIST_ITEM, "Invalid RLP list value.");

        RLPItem[] memory out = new RLPItem[](MAX_LIST_LENGTH);

        uint256 itemCount = 0;
        uint256 offset = listOffset;
        while (offset < _in.length) {
            require(itemCount < MAX_LIST_LENGTH, "Provided RLP list exceeds max list length.");

            (uint256 itemOffset, uint256 itemLength, ) = _decodeLength(
                RLPItem({ length: _in.length - offset, ptr: _in.ptr + offset })
            );

            out[itemCount] = RLPItem({ length: itemLength + itemOffset, ptr: _in.ptr + offset });

            itemCount += 1;
            offset += itemOffset + itemLength;
        }

        assembly {
            mstore(out, itemCount)
        }

        return out;
    }

    function readList(bytes memory _in) internal pure returns (RLPItem[] memory) {

        return readList(toRLPItem(_in));
    }

    function readBytes(RLPItem memory _in) internal pure returns (bytes memory) {

        (uint256 itemOffset, uint256 itemLength, RLPItemType itemType) = _decodeLength(_in);

        require(itemType == RLPItemType.DATA_ITEM, "Invalid RLP bytes value.");

        return _copy(_in.ptr, itemOffset, itemLength);
    }

    function readBytes(bytes memory _in) internal pure returns (bytes memory) {

        return readBytes(toRLPItem(_in));
    }

    function readString(RLPItem memory _in) internal pure returns (string memory) {

        return string(readBytes(_in));
    }

    function readString(bytes memory _in) internal pure returns (string memory) {

        return readString(toRLPItem(_in));
    }

    function readBytes32(RLPItem memory _in) internal pure returns (bytes32) {

        require(_in.length <= 33, "Invalid RLP bytes32 value.");

        (uint256 itemOffset, uint256 itemLength, RLPItemType itemType) = _decodeLength(_in);

        require(itemType == RLPItemType.DATA_ITEM, "Invalid RLP bytes32 value.");

        uint256 ptr = _in.ptr + itemOffset;
        bytes32 out;
        assembly {
            out := mload(ptr)

            if lt(itemLength, 32) {
                out := div(out, exp(256, sub(32, itemLength)))
            }
        }

        return out;
    }

    function readBytes32(bytes memory _in) internal pure returns (bytes32) {

        return readBytes32(toRLPItem(_in));
    }

    function readUint256(RLPItem memory _in) internal pure returns (uint256) {

        return uint256(readBytes32(_in));
    }

    function readUint256(bytes memory _in) internal pure returns (uint256) {

        return readUint256(toRLPItem(_in));
    }

    function readBool(RLPItem memory _in) internal pure returns (bool) {

        require(_in.length == 1, "Invalid RLP boolean value.");

        uint256 ptr = _in.ptr;
        uint256 out;
        assembly {
            out := byte(0, mload(ptr))
        }

        require(out == 0 || out == 1, "Lib_RLPReader: Invalid RLP boolean value, must be 0 or 1");

        return out != 0;
    }

    function readBool(bytes memory _in) internal pure returns (bool) {

        return readBool(toRLPItem(_in));
    }

    function readAddress(RLPItem memory _in) internal pure returns (address) {

        if (_in.length == 1) {
            return address(0);
        }

        require(_in.length == 21, "Invalid RLP address value.");

        return address(uint160(readUint256(_in)));
    }

    function readAddress(bytes memory _in) internal pure returns (address) {

        return readAddress(toRLPItem(_in));
    }

    function readRawBytes(RLPItem memory _in) internal pure returns (bytes memory) {

        return _copy(_in);
    }


    function _decodeLength(RLPItem memory _in)
        private
        pure
        returns (
            uint256,
            uint256,
            RLPItemType
        )
    {

        require(_in.length > 0, "RLP item cannot be null.");

        uint256 ptr = _in.ptr;
        uint256 prefix;
        assembly {
            prefix := byte(0, mload(ptr))
        }

        if (prefix <= 0x7f) {

            return (0, 1, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xb7) {

            uint256 strLen = prefix - 0x80;

            require(_in.length > strLen, "Invalid RLP short string.");

            return (1, strLen, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xbf) {
            uint256 lenOfStrLen = prefix - 0xb7;

            require(_in.length > lenOfStrLen, "Invalid RLP long string length.");

            uint256 strLen;
            assembly {
                strLen := div(mload(add(ptr, 1)), exp(256, sub(32, lenOfStrLen)))
            }

            require(_in.length > lenOfStrLen + strLen, "Invalid RLP long string.");

            return (1 + lenOfStrLen, strLen, RLPItemType.DATA_ITEM);
        } else if (prefix <= 0xf7) {
            uint256 listLen = prefix - 0xc0;

            require(_in.length > listLen, "Invalid RLP short list.");

            return (1, listLen, RLPItemType.LIST_ITEM);
        } else {
            uint256 lenOfListLen = prefix - 0xf7;

            require(_in.length > lenOfListLen, "Invalid RLP long list length.");

            uint256 listLen;
            assembly {
                listLen := div(mload(add(ptr, 1)), exp(256, sub(32, lenOfListLen)))
            }

            require(_in.length > lenOfListLen + listLen, "Invalid RLP long list.");

            return (1 + lenOfListLen, listLen, RLPItemType.LIST_ITEM);
        }
    }

    function _copy(
        uint256 _src,
        uint256 _offset,
        uint256 _length
    ) private pure returns (bytes memory) {

        bytes memory out = new bytes(_length);
        if (out.length == 0) {
            return out;
        }

        uint256 src = _src + _offset;
        uint256 dest;
        assembly {
            dest := add(out, 32)
        }

        for (uint256 i = 0; i < _length / 32; i++) {
            assembly {
                mstore(dest, mload(src))
            }

            src += 32;
            dest += 32;
        }

        uint256 mask;
        unchecked {
            mask = 256**(32 - (_length % 32)) - 1;
        }

        assembly {
            mstore(dest, or(and(mload(src), not(mask)), and(mload(dest), mask)))
        }
        return out;
    }

    function _copy(RLPItem memory _in) private pure returns (bytes memory) {

        return _copy(_in.ptr, 0, _in.length);
    }
}



pragma solidity ^0.8.9;

library Lib_RLPWriter {


    function writeBytes(bytes memory _in) internal pure returns (bytes memory) {

        bytes memory encoded;

        if (_in.length == 1 && uint8(_in[0]) < 128) {
            encoded = _in;
        } else {
            encoded = abi.encodePacked(_writeLength(_in.length, 128), _in);
        }

        return encoded;
    }

    function writeList(bytes[] memory _in) internal pure returns (bytes memory) {

        bytes memory list = _flatten(_in);
        return abi.encodePacked(_writeLength(list.length, 192), list);
    }

    function writeString(string memory _in) internal pure returns (bytes memory) {

        return writeBytes(bytes(_in));
    }

    function writeAddress(address _in) internal pure returns (bytes memory) {

        return writeBytes(abi.encodePacked(_in));
    }

    function writeUint(uint256 _in) internal pure returns (bytes memory) {

        return writeBytes(_toBinary(_in));
    }

    function writeBool(bool _in) internal pure returns (bytes memory) {

        bytes memory encoded = new bytes(1);
        encoded[0] = (_in ? bytes1(0x01) : bytes1(0x80));
        return encoded;
    }


    function _writeLength(uint256 _len, uint256 _offset) private pure returns (bytes memory) {

        bytes memory encoded;

        if (_len < 56) {
            encoded = new bytes(1);
            encoded[0] = bytes1(uint8(_len) + uint8(_offset));
        } else {
            uint256 lenLen;
            uint256 i = 1;
            while (_len / i != 0) {
                lenLen++;
                i *= 256;
            }

            encoded = new bytes(lenLen + 1);
            encoded[0] = bytes1(uint8(lenLen) + uint8(_offset) + 55);
            for (i = 1; i <= lenLen; i++) {
                encoded[i] = bytes1(uint8((_len / (256**(lenLen - i))) % 256));
            }
        }

        return encoded;
    }

    function _toBinary(uint256 _x) private pure returns (bytes memory) {

        bytes memory b = abi.encodePacked(_x);

        uint256 i = 0;
        for (; i < 32; i++) {
            if (b[i] != 0) {
                break;
            }
        }

        bytes memory res = new bytes(32 - i);
        for (uint256 j = 0; j < res.length; j++) {
            res[j] = b[i++];
        }

        return res;
    }

    function _memcpy(
        uint256 _dest,
        uint256 _src,
        uint256 _len
    ) private pure {

        uint256 dest = _dest;
        uint256 src = _src;
        uint256 len = _len;

        for (; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        uint256 mask;
        unchecked {
            mask = 256**(32 - len) - 1;
        }
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    function _flatten(bytes[] memory _list) private pure returns (bytes memory) {

        if (_list.length == 0) {
            return new bytes(0);
        }

        uint256 len;
        uint256 i = 0;
        for (; i < _list.length; i++) {
            len += _list[i].length;
        }

        bytes memory flattened = new bytes(len);
        uint256 flattenedPtr;
        assembly {
            flattenedPtr := add(flattened, 0x20)
        }

        for (i = 0; i < _list.length; i++) {
            bytes memory item = _list[i];

            uint256 listPtr;
            assembly {
                listPtr := add(item, 0x20)
            }

            _memcpy(flattenedPtr, listPtr, item.length);
            flattenedPtr += _list[i].length;
        }

        return flattened;
    }
}



pragma solidity ^0.8.9;

library Lib_BytesUtils {


    function slice(
        bytes memory _bytes,
        uint256 _start,
        uint256 _length
    ) internal pure returns (bytes memory) {

        require(_length + 31 >= _length, "slice_overflow");
        require(_start + _length >= _start, "slice_overflow");
        require(_bytes.length >= _start + _length, "slice_outOfBounds");

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                tempBytes := mload(0x40)

                let lengthmod := and(_length, 31)

                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                mstore(0x40, and(add(mc, 31), not(31)))
            }
            default {
                tempBytes := mload(0x40)

                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    function slice(bytes memory _bytes, uint256 _start) internal pure returns (bytes memory) {

        if (_start >= _bytes.length) {
            return bytes("");
        }

        return slice(_bytes, _start, _bytes.length - _start);
    }

    function toBytes32(bytes memory _bytes) internal pure returns (bytes32) {

        if (_bytes.length < 32) {
            bytes32 ret;
            assembly {
                ret := mload(add(_bytes, 32))
            }
            return ret;
        }

        return abi.decode(_bytes, (bytes32)); // will truncate if input length > 32 bytes
    }

    function toUint256(bytes memory _bytes) internal pure returns (uint256) {

        return uint256(toBytes32(_bytes));
    }

    function toNibbles(bytes memory _bytes) internal pure returns (bytes memory) {

        bytes memory nibbles = new bytes(_bytes.length * 2);

        for (uint256 i = 0; i < _bytes.length; i++) {
            nibbles[i * 2] = _bytes[i] >> 4;
            nibbles[i * 2 + 1] = bytes1(uint8(_bytes[i]) % 16);
        }

        return nibbles;
    }

    function fromNibbles(bytes memory _bytes) internal pure returns (bytes memory) {

        bytes memory ret = new bytes(_bytes.length / 2);

        for (uint256 i = 0; i < ret.length; i++) {
            ret[i] = (_bytes[i * 2] << 4) | (_bytes[i * 2 + 1]);
        }

        return ret;
    }

    function equal(bytes memory _bytes, bytes memory _other) internal pure returns (bool) {

        return keccak256(_bytes) == keccak256(_other);
    }
}



pragma solidity ^0.8.9;

library Lib_Bytes32Utils {


    function toBool(bytes32 _in) internal pure returns (bool) {

        return _in != 0;
    }

    function fromBool(bool _in) internal pure returns (bytes32) {

        return bytes32(uint256(_in ? 1 : 0));
    }

    function toAddress(bytes32 _in) internal pure returns (address) {

        return address(uint160(uint256(_in)));
    }

    function fromAddress(address _in) internal pure returns (bytes32) {

        return bytes32(uint256(uint160(_in)));
    }
}



pragma solidity ^0.8.9;





library Lib_OVMCodec {


    enum QueueOrigin {
        SEQUENCER_QUEUE,
        L1TOL2_QUEUE
    }


    struct EVMAccount {
        uint256 nonce;
        uint256 balance;
        bytes32 storageRoot;
        bytes32 codeHash;
    }

    struct ChainBatchHeader {
        uint256 batchIndex;
        bytes32 batchRoot;
        uint256 batchSize;
        uint256 prevTotalElements;
        bytes extraData;
    }

    struct ChainInclusionProof {
        uint256 index;
        bytes32[] siblings;
    }

    struct Transaction {
        uint256 timestamp;
        uint256 blockNumber;
        QueueOrigin l1QueueOrigin;
        address l1TxOrigin;
        address entrypoint;
        uint256 gasLimit;
        bytes data;
    }

    struct TransactionChainElement {
        bool isSequenced;
        uint256 queueIndex; // QUEUED TX ONLY
        uint256 timestamp; // SEQUENCER TX ONLY
        uint256 blockNumber; // SEQUENCER TX ONLY
        bytes txData; // SEQUENCER TX ONLY
    }

    struct QueueElement {
        bytes32 transactionHash;
        uint40 timestamp;
        uint40 blockNumber;
    }


    function encodeTransaction(Transaction memory _transaction)
        internal
        pure
        returns (bytes memory)
    {

        return
            abi.encodePacked(
                _transaction.timestamp,
                _transaction.blockNumber,
                _transaction.l1QueueOrigin,
                _transaction.l1TxOrigin,
                _transaction.entrypoint,
                _transaction.gasLimit,
                _transaction.data
            );
    }

    function hashTransaction(Transaction memory _transaction) internal pure returns (bytes32) {

        return keccak256(encodeTransaction(_transaction));
    }

    function decodeEVMAccount(bytes memory _encoded) internal pure returns (EVMAccount memory) {

        Lib_RLPReader.RLPItem[] memory accountState = Lib_RLPReader.readList(_encoded);

        return
            EVMAccount({
                nonce: Lib_RLPReader.readUint256(accountState[0]),
                balance: Lib_RLPReader.readUint256(accountState[1]),
                storageRoot: Lib_RLPReader.readBytes32(accountState[2]),
                codeHash: Lib_RLPReader.readBytes32(accountState[3])
            });
    }

    function hashBatchHeader(Lib_OVMCodec.ChainBatchHeader memory _batchHeader)
        internal
        pure
        returns (bytes32)
    {

        return
            keccak256(
                abi.encode(
                    _batchHeader.batchRoot,
                    _batchHeader.batchSize,
                    _batchHeader.prevTotalElements,
                    _batchHeader.extraData
                )
            );
    }
}



pragma solidity >0.5.0 <0.9.0;

interface IChainStorageContainer {


    function setGlobalMetadata(bytes27 _globalMetadata) external;


    function getGlobalMetadata() external view returns (bytes27);


    function length() external view returns (uint256);


    function push(bytes32 _object) external;


    function push(bytes32 _object, bytes27 _globalMetadata) external;


    function setByChainId(
        uint256 _chainId,
        uint256 _index,
        bytes32 _object
    )
        external;

        
    function get(uint256 _index) external view returns (bytes32);


    function deleteElementsAfterInclusive(uint256 _index) external;


    function deleteElementsAfterInclusive(uint256 _index, bytes27 _globalMetadata) external;


    function setGlobalMetadataByChainId(
        uint256 _chainId,
        bytes27 _globalMetadata
    )
        external;


    function getGlobalMetadataByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            bytes27
        );


    function lengthByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint256
        );


    function pushByChainId(
        uint256 _chainId,
        bytes32 _object
    )
        external;


    function pushByChainId(
        uint256 _chainId,
        bytes32 _object,
        bytes27 _globalMetadata
    )
        external;


    function getByChainId(
        uint256 _chainId,
        uint256 _index
    )
        external
        view
        returns (
            bytes32
        );


    function deleteElementsAfterInclusiveByChainId(
        uint256 _chainId,
        uint256 _index
    )
        external;

        
    function deleteElementsAfterInclusiveByChainId(
        uint256 _chainId,
        uint256 _index,
        bytes27 _globalMetadata
    )
        external;

        
}






interface ICanonicalTransactionChain {

    event QueueGlobalMetadataSet(
        address _sender,
        uint256 _chainId,
        bytes27 _globalMetadata
    );
    
    event QueuePushed(
        address _sender,
        uint256 _chainId,
        Lib_OVMCodec.QueueElement _object
    );

    event QueueSetted(
        address _sender,
        uint256 _chainId,
        uint256 _index,
        Lib_OVMCodec.QueueElement _object
    );

    event QueueElementDeleted(
        address _sender,
        uint256 _chainId,
        uint256 _index,
        bytes27 _globalMetadata
    );

    event BatchesGlobalMetadataSet(
        address _sender,
        uint256 _chainId,
        bytes27 _globalMetadata
    );
    
    event BatchPushed(
        address _sender,
        uint256 _chainId,
        bytes32 _object,
        bytes27 _globalMetadata
    );

    event BatchSetted(
        address _sender,
        uint256 _chainId,
        uint256 _index,
        bytes32 _object
    );

    event BatchElementDeleted(
        address _sender,
        uint256 _chainId,
        uint256 _index,
        bytes27 _globalMetadata
    );

    event L2GasParamsUpdated(
        uint256 l2GasDiscountDivisor,
        uint256 enqueueGasCost,
        uint256 enqueueL2GasPrepaid
    );

    event TransactionEnqueued(
        uint256 _chainId,
        address indexed _l1TxOrigin,
        address indexed _target,
        uint256 _gasLimit,
        bytes _data,
        uint256 indexed _queueIndex,
        uint256 _timestamp
    );

    event QueueBatchAppended(
        uint256 _chainId,
        uint256 _startingQueueIndex,
        uint256 _numQueueElements,
        uint256 _totalElements
    );

    event SequencerBatchAppended(
        uint256 _chainId,
        uint256 _startingQueueIndex,
        uint256 _numQueueElements,
        uint256 _totalElements
    );

    event TransactionBatchAppended(
        uint256 _chainId,
        uint256 indexed _batchIndex,
        bytes32 _batchRoot,
        uint256 _batchSize,
        uint256 _prevTotalElements,
        bytes _extraData
    );


    struct BatchContext {
        uint256 numSequencedTransactions;
        uint256 numSubsequentQueueTransactions;
        uint256 timestamp;
        uint256 blockNumber;
    }


    function setGasParams(uint256 _l2GasDiscountDivisor, uint256 _enqueueGasCost) external;



    function batches() external view returns (IChainStorageContainer);


    function queue() external view returns (IChainStorageContainer);


    function getTotalElements() external view returns (uint256 _totalElements);


    function getTotalBatches() external view returns (uint256 _totalBatches);


    function getNextQueueIndex() external view returns (uint40);


    function getQueueElement(uint256 _index)
        external
        view
        returns (Lib_OVMCodec.QueueElement memory _element);


    function getLastTimestamp() external view returns (uint40);


    function getLastBlockNumber() external view returns (uint40);


    function getNumPendingQueueElements() external view returns (uint40);


    function getQueueLength() external view returns (uint40);


    function enqueue(
        address _target,
        uint256 _gasLimit,
        bytes memory _data
    ) external;


    function appendSequencerBatch(
    )
        external;

        
    
    function getTotalElementsByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint256 _totalElements
        );


    function getTotalBatchesByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint256 _totalBatches
        );


    function getNextQueueIndexByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint40
        );


    function getQueueElementByChainId(
        uint256 _chainId,
        uint256 _index
    )
        external
        view
        returns (
            Lib_OVMCodec.QueueElement memory _element
        );


    function getLastTimestampByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint40
        );


    function getLastBlockNumberByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint40
        );


    function getNumPendingQueueElementsByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint40
        );


    function getQueueLengthByChainId(
        uint256 _chainId
        )
        external
        view
        returns (
            uint40
        );



    function enqueueByChainId(
        uint256 _chainId,
        address _target,
        uint256 _gasLimit,
        bytes memory _data
    )
        external;

        
    function appendSequencerBatchByChainId(
    )
        external;

    
    function pushQueueByChainId(
        uint256 _chainId,
        Lib_OVMCodec.QueueElement calldata _object
    )
        external;


    function setQueueByChainId(
        uint256 _chainId,
        uint256 _index,
        Lib_OVMCodec.QueueElement calldata _object
    )
        external;


    function setBatchGlobalMetadataByChainId(
        uint256 _chainId,
        bytes27 _globalMetadata
    )
        external;

    
    function getBatchGlobalMetadataByChainId(uint256 _chainId)
        external
        view
        returns (
            bytes27
        );

        
    function lengthBatchByChainId(uint256 _chainId)
        external
        view
        returns (
            uint256
        );

        
    function pushBatchByChainId(
        uint256 _chainId,
        bytes32 _object,
        bytes27 _globalMetadata
    )
        external;

    
    function setBatchByChainId(
        uint256 _chainId,
        uint256 _index,
        bytes32 _object
    )
        external;

        
    function getBatchByChainId(
        uint256 _chainId,
        uint256 _index
    )
        external
        view
        returns (
            bytes32
        );

        
    function deleteBatchElementsAfterInclusiveByChainId(
        uint256 _chainId,
        uint256 _index,
        bytes27 _globalMetadata
    )
        external;

}



pragma solidity ^0.8.9;

library Lib_MerkleTree {


    function getMerkleRoot(bytes32[] memory _elements) internal pure returns (bytes32) {

        require(_elements.length > 0, "Lib_MerkleTree: Must provide at least one leaf hash.");

        if (_elements.length == 1) {
            return _elements[0];
        }

        uint256[16] memory defaults = [
            0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563,
            0x633dc4d7da7256660a892f8f1604a44b5432649cc8ec5cb3ced4c4e6ac94dd1d,
            0x890740a8eb06ce9be422cb8da5cdafc2b58c0a5e24036c578de2a433c828ff7d,
            0x3b8ec09e026fdc305365dfc94e189a81b38c7597b3d941c279f042e8206e0bd8,
            0xecd50eee38e386bd62be9bedb990706951b65fe053bd9d8a521af753d139e2da,
            0xdefff6d330bb5403f63b14f33b578274160de3a50df4efecf0e0db73bcdd3da5,
            0x617bdd11f7c0a11f49db22f629387a12da7596f9d1704d7465177c63d88ec7d7,
            0x292c23a9aa1d8bea7e2435e555a4a60e379a5a35f3f452bae60121073fb6eead,
            0xe1cea92ed99acdcb045a6726b2f87107e8a61620a232cf4d7d5b5766b3952e10,
            0x7ad66c0a68c72cb89e4fb4303841966e4062a76ab97451e3b9fb526a5ceb7f82,
            0xe026cc5a4aed3c22a58cbd3d2ac754c9352c5436f638042dca99034e83636516,
            0x3d04cffd8b46a874edf5cfae63077de85f849a660426697b06a829c70dd1409c,
            0xad676aa337a485e4728a0b240d92b3ef7b3c372d06d189322bfd5f61f1e7203e,
            0xa2fca4a49658f9fab7aa63289c91b7c7b6c832a6d0e69334ff5b0a3483d09dab,
            0x4ebfd9cd7bca2505f7bef59cc1c12ecc708fff26ae4af19abe852afe9e20c862,
            0x2def10d13dd169f550f578bda343d9717a138562e0093b380a1120789d53cf10
        ];

        bytes memory buf = new bytes(64);

        bytes32 leftSibling;
        bytes32 rightSibling;

        uint256 rowSize = _elements.length;

        uint256 depth = 0;

        uint256 halfRowSize; // rowSize / 2
        bool rowSizeIsOdd; // rowSize % 2 == 1

        while (rowSize > 1) {
            halfRowSize = rowSize / 2;
            rowSizeIsOdd = rowSize % 2 == 1;

            for (uint256 i = 0; i < halfRowSize; i++) {
                leftSibling = _elements[(2 * i)];
                rightSibling = _elements[(2 * i) + 1];
                assembly {
                    mstore(add(buf, 32), leftSibling)
                    mstore(add(buf, 64), rightSibling)
                }

                _elements[i] = keccak256(buf);
            }

            if (rowSizeIsOdd) {
                leftSibling = _elements[rowSize - 1];
                rightSibling = bytes32(defaults[depth]);
                assembly {
                    mstore(add(buf, 32), leftSibling)
                    mstore(add(buf, 64), rightSibling)
                }

                _elements[halfRowSize] = keccak256(buf);
            }

            rowSize = halfRowSize + (rowSizeIsOdd ? 1 : 0);
            depth++;
        }

        return _elements[0];
    }

    function verify(
        bytes32 _root,
        bytes32 _leaf,
        uint256 _index,
        bytes32[] memory _siblings,
        uint256 _totalLeaves
    ) internal pure returns (bool) {

        require(_totalLeaves > 0, "Lib_MerkleTree: Total leaves must be greater than zero.");

        require(_index < _totalLeaves, "Lib_MerkleTree: Index out of bounds.");

        require(
            _siblings.length == _ceilLog2(_totalLeaves),
            "Lib_MerkleTree: Total siblings does not correctly correspond to total leaves."
        );

        bytes32 computedRoot = _leaf;

        for (uint256 i = 0; i < _siblings.length; i++) {
            if ((_index & 1) == 1) {
                computedRoot = keccak256(abi.encodePacked(_siblings[i], computedRoot));
            } else {
                computedRoot = keccak256(abi.encodePacked(computedRoot, _siblings[i]));
            }

            _index >>= 1;
        }

        return _root == computedRoot;
    }


    function _ceilLog2(uint256 _in) private pure returns (uint256) {

        require(_in > 0, "Lib_MerkleTree: Cannot compute ceil(log_2) of 0.");

        if (_in == 1) {
            return 0;
        }

        uint256 val = _in;
        uint256 highest = 0;
        for (uint256 i = 128; i >= 1; i >>= 1) {
            if (val & (((uint256(1) << i) - 1) << i) != 0) {
                highest += i;
                val >>= i;
            }
        }

        if ((uint256(1) << highest) != _in) {
            highest += 1;
        }

        return highest;
    }
}






interface IStateCommitmentChain {


    event StateBatchAppended(
        uint256 _chainId,
        uint256 indexed _batchIndex,
        bytes32 _batchRoot,
        uint256 _batchSize,
        uint256 _prevTotalElements,
        bytes _extraData
    );

    event StateBatchDeleted(
        uint256 _chainId,
        uint256 indexed _batchIndex,
        bytes32 _batchRoot
    );


    
    function batches() external view returns (IChainStorageContainer);

    
    function getTotalElements() external view returns (uint256 _totalElements);


    function getTotalBatches() external view returns (uint256 _totalBatches);


    function getLastSequencerTimestamp() external view returns (uint256 _lastSequencerTimestamp);


    function appendStateBatch(bytes32[] calldata _batch, uint256 _shouldStartAtElement) external;


    function deleteStateBatch(Lib_OVMCodec.ChainBatchHeader memory _batchHeader) external;


    function verifyStateCommitment(
        bytes32 _element,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader,
        Lib_OVMCodec.ChainInclusionProof memory _proof
    ) external view returns (bool _verified);


    function insideFraudProofWindow(Lib_OVMCodec.ChainBatchHeader memory _batchHeader)
        external
        view
        returns (
            bool _inside
        );

        
        
        

    function getTotalElementsByChainId(uint256 _chainId)
        external
        view
        returns (
            uint256 _totalElements
        );


    function getTotalBatchesByChainId(uint256 _chainId)
        external
        view
        returns (
            uint256 _totalBatches
        );


    function getLastSequencerTimestampByChainId(uint256 _chainId)
        external
        view
        returns (
            uint256 _lastSequencerTimestamp
        );

        
    function appendStateBatchByChainId(
        uint256 _chainId,
        bytes32[] calldata _batch,
        uint256 _shouldStartAtElement,
        string calldata proposer
    )
        external;


    function deleteStateBatchByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        external;


    function verifyStateCommitmentByChainId(
        uint256 _chainId,
        bytes32 _element,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader,
        Lib_OVMCodec.ChainInclusionProof memory _proof
    )
        external
        view
        returns (
            bool _verified
        );


    function insideFraudProofWindowByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        external
        view
        returns (
            bool _inside
        );

}



pragma solidity ^0.8.9;

interface IBondManager {


    function isCollateralized(address _who) external view returns (bool);

    function isCollateralizedByChainId(
        uint256 _chainId,
        address _who,
        address _prop
    ) external view returns (bool);

}



pragma solidity ^0.8.9;








contract StateCommitmentChain is IStateCommitmentChain, Lib_AddressResolver {



    uint256 public FRAUD_PROOF_WINDOW;
    uint256 public SEQUENCER_PUBLISH_WINDOW;
    
    
    uint256 public DEFAULT_CHAINID = 1088;



    constructor(
        address _libAddressManager,
        uint256 _fraudProofWindow,
        uint256 _sequencerPublishWindow
    )
        Lib_AddressResolver(_libAddressManager)
    {
        FRAUD_PROOF_WINDOW = _fraudProofWindow;
        SEQUENCER_PUBLISH_WINDOW = _sequencerPublishWindow;
    }
    
    function setFraudProofWindow (uint256 window) public {
        require (msg.sender == resolve("METIS_MANAGER"), "now allowed");
        FRAUD_PROOF_WINDOW = window;
    }


    function batches() public view returns (IChainStorageContainer) {

        return IChainStorageContainer(resolve("ChainStorageContainer-SCC-batches"));
    }

    function getTotalElements() public view returns (uint256 _totalElements) {

        return getTotalElementsByChainId(DEFAULT_CHAINID);
    }

    function getTotalBatches() public view returns (uint256 _totalBatches) {

        return getTotalBatchesByChainId(DEFAULT_CHAINID);
    }

    function getLastSequencerTimestamp() public view returns (uint256 _lastSequencerTimestamp) {

        return getLastSequencerTimestampByChainId(DEFAULT_CHAINID);
    }

    function appendStateBatch(bytes32[] memory _batch, uint256 _shouldStartAtElement) public {

        require (1==0, "don't use");
    }
    
    function deleteStateBatch(Lib_OVMCodec.ChainBatchHeader memory _batchHeader) public {

        deleteStateBatchByChainId(DEFAULT_CHAINID, _batchHeader);
    }

    function verifyStateCommitment(
        bytes32 _element,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader,
        Lib_OVMCodec.ChainInclusionProof memory _proof
    ) public view returns (bool) {

        return verifyStateCommitmentByChainId(DEFAULT_CHAINID, _element, _batchHeader, _proof);
    }

    function insideFraudProofWindow(Lib_OVMCodec.ChainBatchHeader memory _batchHeader)
        public
        view
        returns (bool _inside)
    {

        (uint256 timestamp, ) = abi.decode(_batchHeader.extraData, (uint256, address));

        require(timestamp != 0, "Batch header timestamp cannot be zero");
        return (timestamp + FRAUD_PROOF_WINDOW) > block.timestamp;
    }


    function _getBatchExtraData() internal view returns (uint40, uint40) {

        bytes27 extraData = batches().getGlobalMetadata();

        uint40 totalElements;
        uint40 lastSequencerTimestamp;
        assembly {
            extraData := shr(40, extraData)
            totalElements := and(
                extraData,
                0x000000000000000000000000000000000000000000000000000000FFFFFFFFFF
            )
            lastSequencerTimestamp := shr(
                40,
                and(extraData, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000)
            )
        }

        return (totalElements, lastSequencerTimestamp);
    }

    function _makeBatchExtraData(uint40 _totalElements, uint40 _lastSequencerTimestamp)
        internal
        pure
        returns (bytes27)
    {

        bytes27 extraData;
        assembly {
            extraData := _totalElements
            extraData := or(extraData, shl(40, _lastSequencerTimestamp))
            extraData := shl(40, extraData)
        }

        return extraData;
    }

    function getTotalElementsByChainId(
        uint256 _chainId
        )
        override
        public
        view
        returns (
            uint256 _totalElements
        )
    {

        (uint40 totalElements, ) = _getBatchExtraDataByChainId(_chainId);
        return uint256(totalElements);
    }

    function getTotalBatchesByChainId(
        uint256 _chainId
        )
        override
        public
        view
        returns (
            uint256 _totalBatches
        )
    {

        return batches().lengthByChainId(_chainId);
    }

    function getLastSequencerTimestampByChainId(
        uint256 _chainId
        )
        override
        public
        view
        returns (
            uint256 _lastSequencerTimestamp
        )
    {

        (, uint40 lastSequencerTimestamp) = _getBatchExtraDataByChainId(_chainId);
        return uint256(lastSequencerTimestamp);
    }
    
    function appendStateBatchByChainId(
        uint256 _chainId,
        bytes32[] calldata _batch,
        uint256 _shouldStartAtElement,
        string calldata proposer
    )
        override
        public
    {

        require(
            _shouldStartAtElement == getTotalElementsByChainId(_chainId),
            "Actual batch start index does not match expected start index."
        );
        
        address proposerAddr = resolve(proposer);

        require(
            IBondManager(resolve("BondManager")).isCollateralizedByChainId(_chainId,msg.sender,proposerAddr),
            "Proposer does not have enough collateral posted"
        );

        require(
            _batch.length > 0,
            "Cannot submit an empty state batch."
        );

        require(
            getTotalElementsByChainId(_chainId) + _batch.length <= ICanonicalTransactionChain(resolve("CanonicalTransactionChain")).getTotalElementsByChainId(_chainId),
            "Number of state roots cannot exceed the number of canonical transactions."
        );

        _appendBatchByChainId(
            _chainId,
            _batch,
            abi.encode(block.timestamp, msg.sender),
            proposerAddr
        );
    }

    function deleteStateBatchByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        override
        public
    {

        require(
            msg.sender == resolve(
              string(abi.encodePacked(uint2str(_chainId),"_MVM_FraudVerifier"))),
            "State batches can only be deleted by the MVM_FraudVerifier."
        );

        require(
            _isValidBatchHeaderByChainId(_chainId,_batchHeader),
            "Invalid batch header."
        );

        require(
            insideFraudProofWindowByChainId(_chainId,_batchHeader),
            "State batches can only be deleted within the fraud proof window."
        );

        _deleteBatchByChainId(_chainId,_batchHeader);
    }

    function verifyStateCommitmentByChainId(
        uint256 _chainId,
        bytes32 _element,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader,
        Lib_OVMCodec.ChainInclusionProof memory _proof
    )
        override
        public
        view
        returns (
            bool
        )
    {

        require(
            _isValidBatchHeaderByChainId(_chainId,_batchHeader),
            "Invalid batch header."
        );

        require(
            Lib_MerkleTree.verify(
                _batchHeader.batchRoot,
                _element,
                _proof.index,
                _proof.siblings,
                _batchHeader.batchSize
            ),
            "Invalid inclusion proof."
        );

        return true;
    }

    function insideFraudProofWindowByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        override
        public
        view
        returns (
            bool _inside
        )
    {

        (uint256 timestamp,) = abi.decode(
            _batchHeader.extraData,
            (uint256, address)
        );

        require(
            timestamp != 0,
            "Batch header timestamp cannot be zero"
        );
        return timestamp + FRAUD_PROOF_WINDOW > block.timestamp;
    }
    


    function _getBatchExtraDataByChainId(
        uint256 _chainId
        )
        internal
        view
        returns (
            uint40,
            uint40
        )
    {

        bytes27 extraData = batches().getGlobalMetadataByChainId(_chainId);

        uint40 totalElements;
        uint40 lastSequencerTimestamp;
        assembly {
            extraData              := shr(40, extraData)
            totalElements          :=         and(extraData, 0x000000000000000000000000000000000000000000000000000000FFFFFFFFFF)
            lastSequencerTimestamp := shr(40, and(extraData, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000))
        }

        return (
            totalElements,
            lastSequencerTimestamp
        );
    }

    function _makeBatchExtraDataByChainId(
        uint256 _chainId,
        uint40 _totalElements,
        uint40 _lastSequencerTimestamp
    )
        internal
        pure
        returns (
            bytes27
        )
    {

        bytes27 extraData;
        assembly {
            extraData := _totalElements
            extraData := or(extraData, shl(40, _lastSequencerTimestamp))
            extraData := shl(40, extraData)
        }

        return extraData;
    }

    function _appendBatchByChainId(
        uint256 _chainId,
        bytes32[] memory _batch,
        bytes memory _extraData,
        address proposer
    )
        internal
    {

        (uint40 totalElements, uint40 lastSequencerTimestamp) = _getBatchExtraDataByChainId(_chainId);

        if (msg.sender == proposer) {
            lastSequencerTimestamp = uint40(block.timestamp);
        } else {
            require(
                lastSequencerTimestamp + SEQUENCER_PUBLISH_WINDOW < block.timestamp,
                "Cannot publish state roots within the sequencer publication window."
            );
        }

        Lib_OVMCodec.ChainBatchHeader memory batchHeader = Lib_OVMCodec.ChainBatchHeader({
            batchIndex: getTotalBatchesByChainId(_chainId),
            batchRoot: Lib_MerkleTree.getMerkleRoot(_batch),
            batchSize: _batch.length,
            prevTotalElements: totalElements,
            extraData: _extraData
        });

        emit StateBatchAppended(
            _chainId,
            batchHeader.batchIndex,
            batchHeader.batchRoot,
            batchHeader.batchSize,
            batchHeader.prevTotalElements,
            batchHeader.extraData
        );

        batches().pushByChainId(
            _chainId,
            Lib_OVMCodec.hashBatchHeader(batchHeader),
            _makeBatchExtraDataByChainId(
                _chainId,
                uint40(batchHeader.prevTotalElements + batchHeader.batchSize),
                lastSequencerTimestamp
            )
        );
    }

    function _deleteBatchByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        internal
    {

        require(
            _batchHeader.batchIndex < batches().lengthByChainId(_chainId),
            "Invalid batch index."
        );

        require(
            _isValidBatchHeaderByChainId(_chainId,_batchHeader),
            "Invalid batch header."
        );

        batches().deleteElementsAfterInclusiveByChainId(
            _chainId,
            _batchHeader.batchIndex,
            _makeBatchExtraDataByChainId(
                _chainId,
                uint40(_batchHeader.prevTotalElements),
                0
            )
        );

        emit StateBatchDeleted(
            _chainId,
            _batchHeader.batchIndex,
            _batchHeader.batchRoot
        );
    }

    function _isValidBatchHeaderByChainId(
        uint256 _chainId,
        Lib_OVMCodec.ChainBatchHeader memory _batchHeader
    )
        internal
        view
        returns (
            bool
        )
    {

        return Lib_OVMCodec.hashBatchHeader(_batchHeader) == batches().getByChainId(_chainId,_batchHeader.batchIndex);
    }
    
    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {

        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}



pragma solidity ^0.8.9;







contract MVM_CanonicalTransaction is iMVM_CanonicalTransaction, Lib_AddressResolver{


    string constant public CONFIG_OWNER_KEY = "METIS_MANAGER";

    uint256 constant public TXDATA_SUBMIT_TIMEOUT = 1800;


    uint256 public txDataSliceSize;
    uint256 public stakeSeqSeconds;
    uint256 public stakeBaseCost;
    uint256 public txDataSliceCount;
    uint256 public txBatchSize;
    uint256 public stakeUnitCost;

    bool useWhiteList;


    mapping (address => bool) public whitelist;


    mapping(address => uint256) private verifierStakes;

    mapping(uint256 => mapping(uint256 => BatchElement)) queueBatchElement;

    mapping(uint256 => mapping(uint256 => TxDataRequestStake)) queueTxDataRequestStake;

    mapping(uint256 => mapping(uint256 => TxDataSlice)) queueTxData;


    constructor() Lib_AddressResolver(address(0)) {}


    modifier onlyManager {

        require(
            msg.sender == resolve(CONFIG_OWNER_KEY),
            "MVM_CanonicalTransaction: Function can only be called by the METIS_MANAGER."
        );
        _;
    }

    modifier onlyWhitelisted {

        require(isWhiteListed(msg.sender), "only whitelisted verifiers can call");
        _;
    }


    function setStakeBaseCost(uint256 _stakeBaseCost) override public onlyManager {

        stakeBaseCost = _stakeBaseCost;
    }

    function getStakeBaseCost() override public view returns (uint256) {

        return stakeBaseCost;
    }

    function setStakeUnitCost(uint256 _stakeUnitCost) override public onlyManager {

        stakeUnitCost = _stakeUnitCost;
    }

    function getStakeUnitCost() override public view returns (uint256) {

        return stakeUnitCost;
    }

    function getStakeCostByBatch(uint256 _chainId, uint256 _batchIndex) override public view returns (uint256) {

        require(stakeBaseCost > 0, "stake base cost not config yet");
        require(queueBatchElement[_chainId][_batchIndex].txBatchTime > 0, "batch element does not exist");
        return stakeBaseCost + queueBatchElement[_chainId][_batchIndex].txBatchSize * stakeUnitCost;
    }

    function setTxDataSliceSize(uint256 _size) override public onlyManager {

        require(_size > 0, "slice size should gt 0");
        require(_size != txDataSliceSize, "slice size has not changed");
        txDataSliceSize = _size;
    }

    function getTxDataSliceSize() override public view returns (uint256) {

        return txDataSliceSize;
    }

    function setTxDataSliceCount(uint256 _count) override public onlyManager {

        require(_count > 0, "slice count should gt 0");
        require(_count != txDataSliceCount, "slice count has not changed");
        txDataSliceCount = _count;
    }

    function getTxDataSliceCount() override public view returns (uint256) {

        return txDataSliceCount;
    }

    function setTxBatchSize(uint256 _size) override public onlyManager {

        require(_size > 0, "batch size should gt 0");
        require(_size != txBatchSize, "batch size has not changed");
        txBatchSize = _size;
    }

    function getTxBatchSize() override public view returns (uint256) {

        return txBatchSize;
    }

    function setStakeSeqSeconds(uint256 _seconds) override public onlyManager {

        require(_seconds > 0, "seconds should gt 0");
        require(_seconds != stakeSeqSeconds, "seconds has not changed");
        stakeSeqSeconds = _seconds;
    }

    function getStakeSeqSeconds() override public view returns (uint256) {

        return stakeSeqSeconds;
    }

    function isWhiteListed(address _verifier) override public view returns(bool){

        return !useWhiteList || whitelist[_verifier];
    }

    function setWhiteList(address _verifier, bool _allowed) override public onlyManager {

        whitelist[_verifier] = _allowed;
        useWhiteList = true;
    }

    function disableWhiteList() override public onlyManager {

        useWhiteList = false;
    }

    function appendSequencerBatchByChainId() override public {

        uint256 _chainId;
        uint40 shouldStartAtElement;
        uint24 totalElementsToAppend;
        uint24 numContexts;
        uint256 batchTime;
        uint256 _dataSize;
        uint256 txSize;
        bytes32 root;
        assembly {
            _dataSize             := calldatasize()
            _chainId              := calldataload(4)
            shouldStartAtElement  := shr(216, calldataload(36))
            totalElementsToAppend := shr(232, calldataload(41))
            numContexts           := shr(232, calldataload(44))
        }
        require(
            msg.sender == resolve(string(abi.encodePacked(uint2str(_chainId),"_MVM_Sequencer_Wrapper"))),
            "Function can only be called by the Sequencer."
        );
        uint256 posTs =  47 + 16 * numContexts;
        if (_dataSize > posTs) {
            uint256 posTxSize = 7 + posTs;
            uint256 posRoot =  11 + posTs;
            assembly {
                batchTime := shr(204, calldataload(posTs))
                txSize := shr(224, calldataload(posTxSize))
                root := calldataload(posRoot)
            }

            require(txSize / 2 <= txBatchSize, "size of tx data is too large");
        }

        address ctc = resolve("CanonicalTransactionChain");
        IChainStorageContainer batchesRef = ICanonicalTransactionChain(ctc).batches();
        uint256 batchIndex = batchesRef.lengthByChainId(_chainId);
        {
            (bool success, bytes memory result) = ctc.call(msg.data);
            if (success == false) {
                assembly {
                    let ptr := mload(0x40)
                    let size := returndatasize()
                    returndatacopy(ptr, 0, size)
                    revert(ptr, size)
                }
            }
        }

        queueBatchElement[_chainId][batchIndex] = BatchElement({
            shouldStartAtElement:  shouldStartAtElement,
            totalElementsToAppend: totalElementsToAppend,
            txBatchSize:           txSize,
            txBatchTime:           batchTime,
            root:                  root,
            timestamp:             block.timestamp
        });

        emit AppendBatchElement(
            _chainId,
            batchIndex,
            shouldStartAtElement,
            totalElementsToAppend,
            txSize,
            batchTime,
            root
        );
    }

    function setBatchTxDataForStake(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        bytes memory _data,
        uint256 _leafIndex,
        uint256 _totalLeaves,
        bytes32[] memory _proof
    )
        override
        public
    {

        require(
            msg.sender == resolve(string(abi.encodePacked(uint2str(_chainId),"_MVM_Sequencer_Wrapper"))),
            "Function can only be called by the Sequencer."
        );
        require(queueTxDataRequestStake[_chainId][_blockNumber].timestamp > 0, "there is no stake for this block number");
        require(queueTxDataRequestStake[_chainId][_blockNumber].batchIndex == _batchIndex, "incorrect batch index");
        require(queueTxDataRequestStake[_chainId][_blockNumber].status == STAKESTATUS.INIT, "not allowed to submit");

        _setBatchTxData(_chainId, _batchIndex, _blockNumber, _data, _leafIndex, _totalLeaves,  _proof,  true);

        if (queueTxDataRequestStake[_chainId][_blockNumber].status == STAKESTATUS.INIT) {
            require(
                queueTxDataRequestStake[_chainId][_blockNumber].amount <= verifierStakes[queueTxDataRequestStake[_chainId][_blockNumber].sender],
                "insufficient stake"
            );
            require(
                queueTxDataRequestStake[_chainId][_blockNumber].amount <= address(this).balance,
                "insufficient balance"
            );
            queueTxDataRequestStake[_chainId][_blockNumber].status = STAKESTATUS.SEQ_SET;
            if (queueTxDataRequestStake[_chainId][_blockNumber].amount > 0){
                verifierStakes[queueTxDataRequestStake[_chainId][_blockNumber].sender] -= queueTxDataRequestStake[_chainId][_blockNumber].amount;
                (bool success, ) = payable(msg.sender).call{value: queueTxDataRequestStake[_chainId][_blockNumber].amount}("");
                require(success, "insufficient balance");
                queueTxDataRequestStake[_chainId][_blockNumber].amount = 0;
            }
        }

        emit SetBatchTxData(
            msg.sender,
            _chainId,
            _batchIndex,
            _blockNumber,
            queueTxDataRequestStake[_chainId][_blockNumber].amount,
            true,
            true
        );
    }

    function setBatchTxDataForVerifier(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        bytes memory _data
    )
        override
        public
    {

         require(
            msg.sender != resolve(string(abi.encodePacked(uint2str(_chainId),"_MVM_Sequencer_Wrapper"))),
            "Function can not be called by the Sequencer."
        );
        require(queueTxDataRequestStake[_chainId][_blockNumber].timestamp > 0, "there is no stake for this block number");
        require(queueTxDataRequestStake[_chainId][_blockNumber].batchIndex == _batchIndex, "incorrect batch index");
        require(queueTxDataRequestStake[_chainId][_blockNumber].endtime < block.timestamp, "can not submit during sequencer submit protection");
        if (queueTxDataRequestStake[_chainId][_blockNumber].sender != msg.sender) {
            require(queueTxDataRequestStake[_chainId][_blockNumber].endtime + stakeSeqSeconds < block.timestamp, "can not submit during staker submit protection");
        }

        _setBatchTxData(_chainId, _batchIndex, _blockNumber, _data, 0, 0, new bytes32[](0), false);

        if (queueTxDataRequestStake[_chainId][_blockNumber].status == STAKESTATUS.INIT) {
            queueTxDataRequestStake[_chainId][_blockNumber].status = STAKESTATUS.VERIFIER_SET;

            address claimer = queueTxDataRequestStake[_chainId][_blockNumber].sender;
            if (queueTxDataRequestStake[_chainId][_blockNumber].amount <= verifierStakes[claimer] && queueTxDataRequestStake[_chainId][_blockNumber].amount > 0) {
                require(
                    queueTxDataRequestStake[_chainId][_blockNumber].amount <= address(this).balance,
                    "insufficient balance"
                );
                verifierStakes[claimer] -= queueTxDataRequestStake[_chainId][_blockNumber].amount;
                (bool success, ) = payable(claimer).call{value: queueTxDataRequestStake[_chainId][_blockNumber].amount}("");
                require(success, "insufficient balance");
                queueTxDataRequestStake[_chainId][_blockNumber].amount = 0;
            }
        }

        emit SetBatchTxData(
            msg.sender,
            _chainId,
            _batchIndex,
            _blockNumber,
            queueTxDataRequestStake[_chainId][_blockNumber].amount,
            false,
            false
        );
    }

    function _setBatchTxData(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        bytes memory _data,
        uint256 _leafIndex,
        uint256 _totalLeaves,
        bytes32[] memory _proof,
        bool _requireVerify
    )
        internal
    {

        require(_data.length > 0, "empty data");
        require(queueBatchElement[_chainId][_batchIndex].txBatchTime > 0, "batch element does not exist");
        require(queueBatchElement[_chainId][_batchIndex].totalElementsToAppend > 0, "batch total element to append should not be zero");
       
        if (queueTxData[_chainId][_blockNumber].timestamp > 0) {
            require(queueTxData[_chainId][_blockNumber].verified == false, "tx data verified");
            if (queueTxData[_chainId][_blockNumber].sender != msg.sender) {
                require(queueTxData[_chainId][_blockNumber].timestamp + TXDATA_SUBMIT_TIMEOUT > block.timestamp, "in submitting");

                queueTxData[_chainId][_blockNumber].sender = msg.sender;
                queueTxData[_chainId][_blockNumber].blockNumber = _blockNumber;
                queueTxData[_chainId][_blockNumber].batchIndex = _batchIndex;
                queueTxData[_chainId][_blockNumber].timestamp = block.timestamp;
                queueTxData[_chainId][_blockNumber].txData = _data;
                queueTxData[_chainId][_blockNumber].verified = false;
            }
            else {
                queueTxData[_chainId][_blockNumber].txData = _data;
                queueTxData[_chainId][_blockNumber].verified = false;
            }
        }
        else {
            queueTxData[_chainId][_blockNumber] = TxDataSlice({
                sender:         msg.sender,
                blockNumber:    _blockNumber,
                batchIndex:    _batchIndex,
                timestamp:      block.timestamp,
                txData:         _data,
                verified:       false
            });
        }
        if (_requireVerify) {
            bytes32 currLeaf = keccak256(abi.encodePacked(_blockNumber, _data));
            bool verified = Lib_MerkleTree.verify(queueBatchElement[_chainId][_batchIndex].root, currLeaf, _leafIndex, _proof, _totalLeaves);
            require(verified == true, "tx data verify failed");

            queueTxData[_chainId][_blockNumber].verified = true;
        }
    }

    function getBatchTxData(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber
    )
        override
        external
        view
        returns (
            bytes memory txData,
            bool verified
        )
    {

        require(queueTxData[_chainId][_blockNumber].timestamp != 0, "tx data does not exist");
        require(queueTxData[_chainId][_blockNumber].batchIndex == _batchIndex, "incorrect batch index");
        return (
            queueTxData[_chainId][_blockNumber].txData,
            queueTxData[_chainId][_blockNumber].verified
        );
    }

    function checkBatchTxHash(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        bytes memory _data
    )
        override
        external
        view
        returns (
            bytes32 txHash,
            bool verified
        )
    {

        require(queueTxData[_chainId][_blockNumber].timestamp != 0, "tx data does not exist");
        require(queueTxData[_chainId][_blockNumber].batchIndex == _batchIndex, "incorrect batch index");
        return (
            keccak256(abi.encodePacked(_blockNumber, _data)),
            queueTxData[_chainId][_blockNumber].verified
        );
    }

    function setBatchTxDataVerified(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber,
        bool _verified
    )
        override
        public
        onlyManager
    {

        require(queueTxData[_chainId][_blockNumber].timestamp != 0, "tx data does not exist");
        require(queueTxData[_chainId][_blockNumber].batchIndex == _batchIndex, "incorrect batch index");
        require(queueTxData[_chainId][_blockNumber].verified != _verified, "verified status not change");

        queueTxData[_chainId][_blockNumber].verified = _verified;
    }

    function verifierStake(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber
    )
        override
        public
        payable
        onlyWhitelisted
    {

        uint256 _amount = msg.value;
        uint256 stakeCost = getStakeCostByBatch(_chainId, _batchIndex);
        require(stakeBaseCost > 0, "stake base cost not config yet");
        require(stakeCost == _amount, "stake cost incorrect");
        require(stakeSeqSeconds > 0, "sequencer submit seconds not config yet");
        require(queueBatchElement[_chainId][_batchIndex].txBatchTime > 0, "batch element does not exist");
        require(queueBatchElement[_chainId][_batchIndex].totalElementsToAppend + queueBatchElement[_chainId][_batchIndex].shouldStartAtElement >= _blockNumber && queueBatchElement[_chainId][_batchIndex].shouldStartAtElement < _blockNumber, "block number is not in this batch");
        if (queueTxDataRequestStake[_chainId][_blockNumber].timestamp > 0) {
            require(queueTxDataRequestStake[_chainId][_blockNumber].status == STAKESTATUS.PAYBACK, "there is a stake for this batch index");
        }

        StateCommitmentChain stateChain = StateCommitmentChain(resolve("StateCommitmentChain"));
        require(queueBatchElement[_chainId][_batchIndex].timestamp + stateChain.FRAUD_PROOF_WINDOW() > block.timestamp, "the batch is outside of the fraud proof window");

        queueTxDataRequestStake[_chainId][_blockNumber] = TxDataRequestStake({
            sender:      msg.sender,
            blockNumber: _blockNumber,
            batchIndex:  _batchIndex,
            timestamp:   block.timestamp,
            endtime:     block.timestamp + stakeSeqSeconds,
            amount:      _amount,
            status:      STAKESTATUS.INIT
        });
        verifierStakes[msg.sender] += _amount;

        emit VerifierStake(msg.sender, _chainId, _batchIndex, _blockNumber, _amount);
    }

    function withdrawStake(
        uint256 _chainId,
        uint256 _batchIndex,
        uint256 _blockNumber
    )
        override
        public
    {

        require(queueTxDataRequestStake[_chainId][_blockNumber].timestamp > 0, "there is no stake for this batch index");
        require(queueTxDataRequestStake[_chainId][_blockNumber].amount > 0, "stake amount is zero");
        require(queueTxDataRequestStake[_chainId][_blockNumber].status == STAKESTATUS.INIT, "withdrawals are not allowed");
        require(queueTxDataRequestStake[_chainId][_blockNumber].sender == msg.sender, "can not withdraw other's stake");
        require(queueTxDataRequestStake[_chainId][_blockNumber].endtime < block.timestamp, "can not withdraw during submit protection");
        require(queueTxDataRequestStake[_chainId][_blockNumber].amount <= verifierStakes[msg.sender], "insufficient stake");

        require(
            queueTxDataRequestStake[_chainId][_blockNumber].amount <= address(this).balance,
            "insufficient balance"
        );
        queueTxDataRequestStake[_chainId][_blockNumber].status = STAKESTATUS.PAYBACK;
        verifierStakes[msg.sender] -= queueTxDataRequestStake[_chainId][_blockNumber].amount;
        (bool success, ) = payable(msg.sender).call{value: queueTxDataRequestStake[_chainId][_blockNumber].amount}("");
        require(success, "insufficient balance");
        queueTxDataRequestStake[_chainId][_blockNumber].amount = 0;
    }

    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {

        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}