pragma solidity ^0.5.8;

contract Owned {

    constructor() public { owner = msg.sender; }
    address payable public owner;

    modifier onlyOwner {

        require(
            msg.sender == owner,
            "Only owner can call this function."
        );
        _;
    }

    function transferOwnership(address payable newOwner) external onlyOwner {

        owner = newOwner;
    }
}
pragma solidity ^0.5.8;


contract Swap is Owned {

    uint public refundDelay = 4 * 60 * 4;

    uint constant MAX_REFUND_DELAY = 60 * 60 * 2 * 4;

    function setRefundDelay(uint delay) external onlyOwner {

        require(delay <= MAX_REFUND_DELAY, "Delay is too large.");
        refundDelay = delay;
    }
}
pragma solidity ^0.5.8;

contract ERC20Interface {

    function totalSupply() public view returns (uint);

    function balanceOf(address tokenOwner) public view returns (uint balance);

    function allowance(address tokenOwner, address spender) public view returns (uint remaining);

    function transfer(address to, uint tokens) public returns (bool success);

    function approve(address spender, uint tokens) public returns (bool success);

    function transferFrom(address from, address to, uint tokens) public returns (bool success);


    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
pragma solidity ^0.5.8;


contract ERC20Swap is Swap {

    enum OrderState { HasFundingBalance, Claimed, Refunded }

    struct SwapOrder {
        address user;
        address tokenContractAddress;
        bytes32 paymentHash;
        bytes32 preimage;
        uint onchainAmount;
        uint refundBlockHeight;
        OrderState state;
        bool exist;
    }

    mapping(bytes16 => SwapOrder) orders;

    event OrderFundingReceived(
        bytes16 orderUUID,
        uint onchainAmount,
        bytes32 paymentHash,
        uint refundBlockHeight,
        address tokenContractAddress
    );
    event OrderClaimed(bytes16 orderUUID);
    event OrderRefunded(bytes16 orderUUID);

    function fund(bytes16 orderUUID, bytes32 paymentHash, address tokenContractAddress, uint tokenAmount) external {

        SwapOrder storage order = orders[orderUUID];

        if (!order.exist) {
            order.user = msg.sender;
            order.tokenContractAddress = tokenContractAddress;
            order.exist = true;
            order.paymentHash = paymentHash;
            order.refundBlockHeight = block.number + refundDelay;
            order.state = OrderState.HasFundingBalance;
            order.onchainAmount = 0;
        } else {
            require(order.state == OrderState.HasFundingBalance, "Order already claimed or refunded.");
        }

        require(order.tokenContractAddress == tokenContractAddress, "Incorrect token.");
        require(ERC20Interface(tokenContractAddress).transferFrom(msg.sender, address(this), tokenAmount), "Unable to transfer token.");

        order.onchainAmount += tokenAmount;

        emit OrderFundingReceived(
            orderUUID,
            order.onchainAmount,
            order.paymentHash,
            order.refundBlockHeight,
            order.tokenContractAddress
        );
    }

    function claim(bytes16 orderUUID, address tokenContractAddress, bytes32 preimage) external {

        SwapOrder storage order = orders[orderUUID];

        require(order.exist == true, "Order does not exist.");
        require(order.state == OrderState.HasFundingBalance, "Order cannot be claimed.");
        require(sha256(abi.encodePacked(preimage)) == order.paymentHash, "Incorrect payment preimage.");
        require(block.number <= order.refundBlockHeight, "Too late to claim.");

        order.preimage = preimage;
        ERC20Interface(tokenContractAddress).transfer(owner, order.onchainAmount);
        order.state = OrderState.Claimed;

        emit OrderClaimed(orderUUID);
    }

    function refund(bytes16 orderUUID, address tokenContractAddress) external {

        SwapOrder storage order = orders[orderUUID];

        require(order.exist == true, "Order does not exist.");
        require(order.state == OrderState.HasFundingBalance, "Order cannot be refunded.");
        require(block.number > order.refundBlockHeight, "Too early to refund.");

        ERC20Interface(tokenContractAddress).transfer(order.user, order.onchainAmount);
        order.state = OrderState.Refunded;

        emit OrderRefunded(orderUUID);
    }
}
