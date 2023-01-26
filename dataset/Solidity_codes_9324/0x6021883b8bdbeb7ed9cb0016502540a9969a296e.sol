pragma solidity ^0.7.0;

library LibRichErrors {


    bytes4 internal constant STANDARD_ERROR_SELECTOR =
        0x08c379a0;

    function StandardError(
        string memory message
    )
        internal
        pure
        returns (bytes memory)
    {

        return abi.encodeWithSelector(
            STANDARD_ERROR_SELECTOR,
            bytes(message)
        );
    }

    function rrevert(bytes memory errorData)
        internal
        pure
    {

        assembly {
            revert(add(errorData, 0x20), mload(errorData))
        }
    }
}pragma solidity ^0.7.0;


library LibSafeMathRichErrors {


    bytes4 internal constant UINT256_BINOP_ERROR_SELECTOR =
        0xe946c1bb;

    bytes4 internal constant UINT256_DOWNCAST_ERROR_SELECTOR =
        0xc996af7b;

    enum BinOpErrorCodes {
        ADDITION_OVERFLOW,
        MULTIPLICATION_OVERFLOW,
        SUBTRACTION_UNDERFLOW,
        DIVISION_BY_ZERO
    }

    enum DowncastErrorCodes {
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT32,
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT64,
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT96
    }

    function Uint256BinOpError(
        BinOpErrorCodes errorCode,
        uint256 a,
        uint256 b
    )
        internal
        pure
        returns (bytes memory)
    {

        return abi.encodeWithSelector(
            UINT256_BINOP_ERROR_SELECTOR,
            errorCode,
            a,
            b
        );
    }

    function Uint256DowncastError(
        DowncastErrorCodes errorCode,
        uint256 a
    )
        internal
        pure
        returns (bytes memory)
    {

        return abi.encodeWithSelector(
            UINT256_DOWNCAST_ERROR_SELECTOR,
            errorCode,
            a
        );
    }
}pragma solidity ^0.7.0;


library LibSafeMath {


    function safeMul(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        if (c / a != b) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.MULTIPLICATION_OVERFLOW,
                a,
                b
            ));
        }
        return c;
    }

    function safeDiv(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        if (b == 0) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.DIVISION_BY_ZERO,
                a,
                b
            ));
        }
        uint256 c = a / b;
        return c;
    }

    function safeSub(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        if (b > a) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.SUBTRACTION_UNDERFLOW,
                a,
                b
            ));
        }
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        uint256 c = a + b;
        if (c < a) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.ADDITION_OVERFLOW,
                a,
                b
            ));
        }
        return c;
    }

    function max256(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        return a >= b ? a : b;
    }

    function min256(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {

        return a < b ? a : b;
    }
}pragma solidity ^0.7.0;


library LibAddress {


    function isContract(address account) internal view returns (bool) {

        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

}/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.7.0;

interface IERC1155 {


    event TransferSingle(
        address indexed _operator,
        address indexed _from,
        address indexed _to,
        uint256 _id,
        uint256 _value
    );

    event TransferBatch(
        address indexed _operator,
        address indexed _from,
        address indexed _to,
        uint256[] _ids,
        uint256[] _values
    );

    event ApprovalForAll(
        address indexed _owner,
        address indexed _operator,
        bool _approved
    );

    event URI(
        string _value,
        uint256 indexed _id
    );

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external;


    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external;


    function setApprovalForAll(address operator, bool approved) external;


    function isApprovedForAll(address owner, address operator) external view returns (bool);


    function balanceOf(address owner, uint256 id) external view returns (uint256);


    function balanceOfBatch(
        address[] calldata owners,
        uint256[] calldata ids
    )
        external
        view
        returns (uint256[] memory balances_);

}/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.7.0;


interface IERC1155Receiver {


    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external
        returns(bytes4);


    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external
        returns(bytes4);

}pragma solidity ^0.7.0;


contract MixinNonFungibleToken {

    uint256 constant internal TYPE_MASK = uint256(uint128(~0)) << 128;

    uint256 constant internal NF_INDEX_MASK = uint128(~0);

    uint256 constant internal TYPE_NF_BIT = 1 << 255;

    mapping (uint256 => address) internal nfOwners;

    function isNonFungible(uint256 id) public pure returns(bool) {

        return id & TYPE_NF_BIT == TYPE_NF_BIT;
    }

    function isFungible(uint256 id) public pure returns(bool) {

        return id & TYPE_NF_BIT == 0;
    }

    function getNonFungibleIndex(uint256 id) public pure returns(uint256) {

        return id & NF_INDEX_MASK;
    }

    function getNonFungibleBaseType(uint256 id) public pure returns(uint256) {

        return id & TYPE_MASK;
    }

    function isNonFungibleBaseType(uint256 id) public pure returns(bool) {

        return (id & TYPE_NF_BIT == TYPE_NF_BIT) && (id & NF_INDEX_MASK == 0);
    }

    function isNonFungibleItem(uint256 id) public pure returns(bool) {

        return (id & TYPE_NF_BIT == TYPE_NF_BIT) && (id & NF_INDEX_MASK != 0);
    }

    function ownerOf(uint256 id) public view returns (address) {

        return nfOwners[id];
    }
}pragma solidity ^0.7.0;

contract Context {

    function _msgSender() internal view returns (address payable) {

        return msg.sender;
    }

    function _msgData() internal view returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}// MIT
pragma solidity ^0.7.0;


abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}pragma solidity ^0.7.0;


contract WhitelistExchangesProxy is Ownable {

    mapping(address => bool) internal proxies;

    bool public paused = true;
    
    function setPaused(bool newPaused) external onlyOwner() {

        paused = newPaused;
    }

    function updateProxyAddress(address proxy, bool status) external onlyOwner() {

        proxies[proxy] = status;
    }

    function isAddressWhitelisted(address proxy) external view returns (bool) {

        if (paused) {
            return false;
        } else {
            return proxies[proxy];
        }
    }
}pragma solidity ^0.7.0;


contract ERC1155 is
    IERC1155,
    MixinNonFungibleToken,
    Ownable
{

    using LibAddress for address;
    using LibSafeMath for uint256;

    bytes4 constant public ERC1155_RECEIVED       = 0xf23a6e61;
    bytes4 constant public ERC1155_BATCH_RECEIVED = 0xbc197c81;

    mapping (uint256 => mapping(address => uint256)) internal balances;

    mapping (address => mapping(address => bool)) internal operatorApproval;

    address public exchangesRegistry;

    function setExchangesRegistry(address newExchangesRegistry) external onlyOwner() {

        exchangesRegistry = newExchangesRegistry;
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        override
        external
    {

        require(
            to != address(0x0),
            "CANNOT_TRANSFER_TO_ADDRESS_ZERO"
        );
        require(
            from == msg.sender || isApprovedForAll(from, msg.sender),
            "INSUFFICIENT_ALLOWANCE"
        );

        if (isNonFungible(id)) {
            require(
                    value == 1,
                    "AMOUNT_EQUAL_TO_ONE_REQUIRED"
            );
            require(
                nfOwners[id] == from,
                "NFT_NOT_OWNED_BY_FROM_ADDRESS"
            );
            nfOwners[id] = to;
        } else {
            balances[id][from] = balances[id][from].safeSub(value);
            balances[id][to] = balances[id][to].safeAdd(value);
        }
        emit TransferSingle(msg.sender, from, to, id, value);

        if (to.isContract()) {
            bytes4 callbackReturnValue = IERC1155Receiver(to).onERC1155Received(
                msg.sender,
                from,
                id,
                value,
                data
            );
            require(
                callbackReturnValue == ERC1155_RECEIVED,
                "BAD_RECEIVER_RETURN_VALUE"
            );
        }
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        override
        external
    {

        require(
            to != address(0x0),
            "CANNOT_TRANSFER_TO_ADDRESS_ZERO"
        );
        require(
            ids.length == values.length,
            "TOKEN_AND_VALUES_LENGTH_MISMATCH"
        );

        require(
            from == msg.sender || isApprovedForAll(from, msg.sender),
            "INSUFFICIENT_ALLOWANCE"
        );

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 value = values[i];

            if (isNonFungible(id)) {
                require(
                    value == 1,
                    "AMOUNT_EQUAL_TO_ONE_REQUIRED"
                );
                require(
                    nfOwners[id] == from,
                    "NFT_NOT_OWNED_BY_FROM_ADDRESS"
                );
                nfOwners[id] = to;
            } else {
                balances[id][from] = balances[id][from].safeSub(value);
                balances[id][to] = balances[id][to].safeAdd(value);
            }
        }
        emit TransferBatch(msg.sender, from, to, ids, values);

        if (to.isContract()) {
            bytes4 callbackReturnValue = IERC1155Receiver(to).onERC1155BatchReceived(
                msg.sender,
                from,
                ids,
                values,
                data
            );
            require(
                callbackReturnValue == ERC1155_BATCH_RECEIVED,
                "BAD_RECEIVER_RETURN_VALUE"
            );
        }
    }

    function setApprovalForAll(address operator, bool approved) external override {

        operatorApproval[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public override view returns (bool) {

        bool approved = operatorApproval[owner][operator];
        if (!approved && exchangesRegistry != address(0)) {
            return WhitelistExchangesProxy(exchangesRegistry).isAddressWhitelisted(operator) == true;
        }
        return approved;
    }

    function balanceOf(address owner, uint256 id) external override view returns (uint256) {

        if (isNonFungibleItem(id)) {
            return nfOwners[id] == owner ? 1 : 0;
        }
        return balances[id][owner];
    }

    function balanceOfBatch(address[] calldata owners, uint256[] calldata ids) external override view returns (uint256[] memory balances_) {

        require(
            owners.length == ids.length,
            "OWNERS_AND_IDS_MUST_HAVE_SAME_LENGTH"
        );

        balances_ = new uint256[](owners.length);
        for (uint256 i = 0; i < owners.length; ++i) {
            uint256 id = ids[i];
            if (isNonFungibleItem(id)) {
                balances_[i] = nfOwners[id] == owners[i] ? 1 : 0;
            } else {
                balances_[i] = balances[id][owners[i]];
            }
        }

        return balances_;
    }

    bytes4 constant private INTERFACE_SIGNATURE_ERC165 = 0x01ffc9a7;
    bytes4 constant private INTERFACE_SIGNATURE_ERC1155 = 0xd9b67a26;

    function supportsInterface(bytes4 _interfaceID) external view returns (bool) {

        if (_interfaceID == INTERFACE_SIGNATURE_ERC165 ||
            _interfaceID == INTERFACE_SIGNATURE_ERC1155) {
        return true;
        }
        return false;
    }
}/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.7.0;



interface IERC1155Mintable is
    IERC1155
{


    function create(
        bool isNF
    )
        external
        returns (uint256 type_);


    function mintFungible(
        uint256 id,
        address[] calldata to,
        uint256[] calldata quantities
    )
        external;


    function mintNonFungible(
        uint256 type_,
        address[] calldata to
    )
        external;

}pragma solidity ^0.7.0;


contract MixinContractURI is Ownable {

    string public contractURI;

    function setContractURI(string calldata newContractURI) external onlyOwner() {

        contractURI = newContractURI;
    }
}pragma solidity ^0.7.0;

library LibString {

  function strConcat(string memory _a, string memory _b, string memory _c, string memory _d, string memory _e) internal pure returns (string memory) {

      bytes memory _ba = bytes(_a);
      bytes memory _bb = bytes(_b);
      bytes memory _bc = bytes(_c);
      bytes memory _bd = bytes(_d);
      bytes memory _be = bytes(_e);
      string memory abcde = new string(_ba.length + _bb.length + _bc.length + _bd.length + _be.length);
      bytes memory babcde = bytes(abcde);
      uint k = 0;
      for (uint i = 0; i < _ba.length; i++) babcde[k++] = _ba[i];
      for (uint i = 0; i < _bb.length; i++) babcde[k++] = _bb[i];
      for (uint i = 0; i < _bc.length; i++) babcde[k++] = _bc[i];
      for (uint i = 0; i < _bd.length; i++) babcde[k++] = _bd[i];
      for (uint i = 0; i < _be.length; i++) babcde[k++] = _be[i];
      return string(babcde);
    }

    function strConcat(string memory _a, string memory _b, string memory _c, string memory _d) internal pure returns (string memory) {

        return strConcat(_a, _b, _c, _d, "");
    }

    function strConcat(string memory _a, string memory _b, string memory _c) internal pure returns (string memory) {

        return strConcat(_a, _b, _c, "", "");
    }

    function strConcat(string memory _a, string memory _b) internal pure returns (string memory) {

        return strConcat(_a, _b, "", "", "");
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
        uint k = len - 1;
        while (_i != 0) {
            bstr[k--] = byte(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }

    function uint2hexstr(uint i) internal pure returns (string memory) {

        if (i == 0) {
            return "0";
        }
        uint j = i;
        uint len;
        while (j != 0) {
            len++;
            j = j >> 4;
        }
        uint mask = 15;
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (i != 0){
            uint curr = (i & mask);
            bstr[k--] = curr > 9 ? byte(uint8(55 + curr)) : byte(uint8(48 + curr));
            i = i >> 4;
        }
        return string(bstr);
    }
}pragma solidity ^0.7.0;


contract MixinTokenURI is Ownable {

    using LibString for string;

    string public baseMetadataURI = "";

    function setBaseMetadataURI(string memory newBaseMetadataURI) public onlyOwner() {

        baseMetadataURI = newBaseMetadataURI;
    }

    function uri(uint256 _id) public view returns (string memory) {

        return LibString.strConcat(
        baseMetadataURI,
        LibString.uint2hexstr(_id)
        );
    }
}pragma solidity ^0.7.0;


contract ERC1155Mintable is
    IERC1155Mintable,
    ERC1155,
    MixinContractURI,
    MixinTokenURI
{

    using LibSafeMath for uint256;
    using LibAddress for address;

    uint256 internal nonce;

    mapping (uint256 => uint256) public maxIndex;

    mapping (uint256 => mapping(address => bool)) internal creatorApproval;

    modifier onlyCreator(uint256 _id) {

        require(creatorApproval[_id][msg.sender], "not an approved creator of id");
        _;
    }

    function setCreatorApproval(uint256 id, address creator, bool status) external onlyCreator(id) {

        creatorApproval[id][creator] = status;
    }

    function create(
        bool isNF
    )
        external
        override
        onlyOwner()
        returns (uint256 type_)
    {

        type_ = (++nonce << 128);

        if (isNF) {
            type_ = type_ | TYPE_NF_BIT;
        }

        creatorApproval[type_][msg.sender] = true;

        emit TransferSingle(
            msg.sender,
            address(0x0),
            address(0x0),
            type_,
            0
        );

        emit URI(uri(type_), type_);
    }

    function createWithType(
        uint256 type_
    )
        external
        onlyOwner()
    {


        creatorApproval[type_][msg.sender] = true;

        emit TransferSingle(
            msg.sender,
            address(0x0),
            address(0x0),
            type_,
            0
        );

        emit URI(uri(type_), type_);
    }

    function mintFungible(
        uint256 id,
        address[] calldata to,
        uint256[] calldata quantities
    )
        external
        override
        onlyCreator(id)
    {

        require(
            isFungible(id),
            "TRIED_TO_MINT_FUNGIBLE_FOR_NON_FUNGIBLE_TOKEN"
        );

        for (uint256 i = 0; i < to.length; ++i) {
            address dst = to[i];
            uint256 quantity = quantities[i];

            balances[id][dst] = quantity.safeAdd(balances[id][dst]);

            emit TransferSingle(
                msg.sender,
                address(0x0),
                dst,
                id,
                quantity
            );

            if (dst.isContract()) {
                bytes4 callbackReturnValue = IERC1155Receiver(dst).onERC1155Received(
                    msg.sender,
                    msg.sender,
                    id,
                    quantity,
                    ""
                );
                require(
                    callbackReturnValue == ERC1155_RECEIVED,
                    "BAD_RECEIVER_RETURN_VALUE"
                );
            }
        }
    }

    function mintNonFungible(
        uint256 type_,
        address[] calldata to
    )
        external
        override
        onlyCreator(type_)
    {

        require(
            isNonFungible(type_),
            "TRIED_TO_MINT_NON_FUNGIBLE_FOR_FUNGIBLE_TOKEN"
        );

        uint256 index = maxIndex[type_] + 1;

        for (uint256 i = 0; i < to.length; ++i) {
            address dst = to[i];
            uint256 id  = type_ | index + i;

            nfOwners[id] = dst;

            balances[type_][dst] = balances[type_][dst].safeAdd(1);

            emit TransferSingle(msg.sender, address(0x0), dst, id, 1);

            if (dst.isContract()) {
                bytes4 callbackReturnValue = IERC1155Receiver(dst).onERC1155Received(
                    msg.sender,
                    msg.sender,
                    id,
                    1,
                    ""
                );
                require(
                    callbackReturnValue == ERC1155_RECEIVED,
                    "BAD_RECEIVER_RETURN_VALUE"
                );
            }
        }

        maxIndex[type_] = to.length.safeAdd(maxIndex[type_]);
    }
}// MIT

pragma solidity ^0.7.0;


abstract contract MixinPausable is Context {
    event Paused(address account);

    event Unpaused(address account);

    bool private _paused;

    constructor () {
        _paused = false;
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}pragma solidity ^0.7.0;


contract MixinSignature {

  function splitSignature(bytes memory sig)
      public pure returns (bytes32 r, bytes32 s, uint8 v)
  {

      require(sig.length == 65, "invalid signature length");

      assembly {
          r := mload(add(sig, 32))
          s := mload(add(sig, 64))
          v := byte(0, mload(add(sig, 96)))
      }

      if (v < 27) v += 27;
  }

  function isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {

      return _isSigned(_address, messageHash, v, r, s) || _isSignedPrefixed(_address, messageHash, v, r, s);
  }

  function _isSigned(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
      internal pure returns (bool)
  {

      return ecrecover(messageHash, v, r, s) == _address;
  }

  function _isSignedPrefixed(address _address, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
      internal pure returns (bool)
  {

      bytes memory prefix = "\x19Ethereum Signed Message:\n32";
      return _isSigned(_address, keccak256(abi.encodePacked(prefix, messageHash)), v, r, s);
  }
  
}pragma solidity ^0.7.0;


contract HashRegistry is Ownable {

  using LibSafeMath for uint256;

  ERC1155Mintable public mintableErc1155;

  mapping(uint256 => uint256) public tokenIdToTxHash;
  mapping(uint256 => uint256) public txHashToTokenId;
  mapping(address => bool) public permissedWriters;

  constructor(
    address _mintableErc1155
  ) {
    permissedWriters[msg.sender] = true;
    mintableErc1155 = ERC1155Mintable(_mintableErc1155);
  }

  event UpdatedRegistry(
      uint256 tokenId,
      uint256 txHash
  );

  modifier onlyIfPermissed(address writer) {

    require(permissedWriters[writer] == true, "writer can't write to registry");
    _;
  }

  function updatePermissedWriterStatus(address _writer, bool status) public onlyIfPermissed(msg.sender) {

    permissedWriters[_writer] = status;
  }

  function writeToRegistry(uint256[] memory tokenIds, uint256[] memory txHashes) public onlyIfPermissed(msg.sender) {

    require(tokenIds.length == txHashes.length, "tokenIds and txHashes size mismatch");
    for (uint256 i = 0; i < tokenIds.length; ++i) {
      uint256 tokenId = tokenIds[i];
      uint256 txHash = txHashes[i];
      require(mintableErc1155.ownerOf(tokenId) != address(0), 'token does not exist');
      require(txHashToTokenId[txHash] == 0, 'txHash already exists');
      require(tokenIdToTxHash[tokenId] == 0, 'tokenId already exists');
      tokenIdToTxHash[tokenId] = txHash;
      txHashToTokenId[txHash] = tokenId;
      emit UpdatedRegistry(tokenId, txHash); 
    }
  }
}// MIT

pragma solidity ^0.7.0;

abstract contract ReentrancyGuard {

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        _status = _ENTERED;

        _;

        _status = _NOT_ENTERED;
    }
}pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;


contract SagaPersonalMinter is Ownable, MixinPausable, MixinSignature, ReentrancyGuard {

  using LibSafeMath for uint256;

  uint256 public tokenType;

  ERC1155Mintable public mintableErc1155;
  HashRegistry public registry;

  uint256 public flatPriceForPersonal;

  uint256 immutable maxMintingSupply;

  address payable public treasury;
  address public verifier;

  struct SignedMint {
    address dst;
    uint256 txHash;
    uint256 salt;
    bytes signature;
  }

  constructor(
    address _registry,
    address _mintableErc1155,
    address _verifier,
    address payable _treasury,
    uint256 _tokenType,
    uint256 _flatPriceForPersonal,
    uint256 _maxMintingSupply
  ) {
    registry = HashRegistry(_registry);
    mintableErc1155 = ERC1155Mintable(_mintableErc1155);
    treasury = _treasury;
    tokenType = _tokenType;
    verifier = _verifier;
    flatPriceForPersonal = _flatPriceForPersonal;
    maxMintingSupply = _maxMintingSupply;
  }

  modifier onlyUnderMaxSupply(uint256 mintingAmount) {

    require(maxIndex() + mintingAmount <= maxMintingSupply, 'max supply minted');
    _;
  }

  function pause() external onlyOwner() {

    _pause();
  } 

  function unpause() external onlyOwner() {

    _unpause();
  }  

  function setTreasury(address payable _treasury) external onlyOwner() {

    treasury = _treasury;
  }

  function setFlatPriceForPersonal(uint256 _flatPriceForPersonal) external onlyOwner() {

    flatPriceForPersonal = _flatPriceForPersonal;
  }

  function setVerifier(address _verifier) external onlyOwner() {

    verifier = _verifier;
  }

  function maxIndex() public view returns (uint256) {

    return mintableErc1155.maxIndex(tokenType);
  }

  function getSignedMintHash(SignedMint memory signedMint) public pure returns(bytes32) {

      return keccak256(abi.encodePacked(signedMint.dst, signedMint.txHash, signedMint.salt)) ;
  }

  function verifyPersonalMint(address signer, SignedMint memory signedMint) public pure returns(bool) {

    bytes32 signedHash = getSignedMintHash(signedMint);
    (bytes32 r, bytes32 s, uint8 v) = splitSignature(signedMint.signature);
    return isSigned(signer, signedHash, v, r, s);
  }

  function mint(SignedMint[] memory signedMints) public payable nonReentrant() whenNotPaused() onlyUnderMaxSupply(signedMints.length) {

    for (uint256 i = 0; i < signedMints.length; ++i) {
      require(verifyPersonalMint(verifier, signedMints[i]) == true, 'invalid signature');
    }

    address[] memory dsts = new address[](signedMints.length);
    uint256[] memory txHashes = new uint256[](signedMints.length);
    for (uint256 i = 0; i < signedMints.length; ++i) {
      dsts[i] = signedMints[i].dst;
      txHashes[i] = signedMints[i].txHash;
    }
    _mint(dsts, txHashes);

    uint256 price = flatPriceForPersonal * signedMints.length;
    require(price <= msg.value, "insufficient funds to pay for mint");
    treasury.call{value: price }("");
    msg.sender.call{value: msg.value.safeSub(price) }("");
  }

  function _mint(address[] memory dsts, uint256[] memory txHashes) internal {

    uint256[] memory tokenIds = new uint256[](dsts.length);
    for (uint256 i = 0; i < dsts.length; ++i) {
      uint256 index = maxIndex() + 1 + i;
      uint256 tokenId  = tokenType | index;
      tokenIds[i] = tokenId;
    }
    mintableErc1155.mintNonFungible(tokenType, dsts);
    registry.writeToRegistry(tokenIds, txHashes);
  }
}