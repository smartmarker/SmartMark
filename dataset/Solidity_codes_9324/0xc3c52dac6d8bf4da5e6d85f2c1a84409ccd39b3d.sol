

pragma solidity 0.8.9;




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


contract RedEnvelop {


    uint256 private constant ExpireDay = 1 days;
    uint256 private constant CloseoutDay = ExpireDay * 30;
    uint256 private constant BonusMamb = 8 ether;
    uint256 private constant LuckyDrawMamb = 24 ether;

    uint256 public counter;

    address payable public owner;

    address public mambaCoinAddr;

    struct RedEnvelopInfo {
        uint16 count;
        uint16 remainCount;
        bool isPublic;
        address creator;
        address tokenAddr;
        uint256 createTime;
        uint256 money;
        uint256 remainMoney;
        mapping (address => bool) candidates;
        mapping (address => uint256) recipientInfos;
        mapping (address => uint256) luckydrawInfos;
    }

    mapping (uint256 => RedEnvelopInfo) public redEnvelopInfos;
    constructor() public {
        counter = 0;
        owner = payable(msg.sender);
    }

    function initShareholder(address initTokenAddr) external {

        require(mambaCoinAddr == address(0), "Already Initialized");
        mambaCoinAddr = initTokenAddr;
    }

    event Create(uint256 envelopId, uint exprTime, uint closeoutTime);
    event Open(uint256 envelopId, uint256 money, uint256 remainMoney, uint16 remainCount);
    event LuckyDraw(uint256 envelopId, uint256 money, uint256 remainMoney, uint16 remainCount);
    event DrawBack(uint256 envelopId, uint256 money);
    event CloseOut(uint256 envelopId, uint256 money);

    function create(address tokenAddr, uint256 money, uint16 count, address[] memory candidates) external payable returns (uint256) {

        require(count > 0, "Invalid count");
        require(money >= count, "Invalid money");

        uint256 envelopId = counter;
        RedEnvelopInfo storage p = redEnvelopInfos[envelopId];
        p.count = count;
        p.remainCount = count;
        p.creator = msg.sender;
        p.tokenAddr = tokenAddr;
        p.createTime = block.timestamp;
        p.money = money;
        p.remainMoney = money;

        if (candidates.length > 0) {
            p.isPublic = false;
            for (uint i=0; i<candidates.length; i++) {
                p.candidates[candidates[i]] = true;
            }
        } else {
            p.isPublic = true;
        }

        counter = counter + 1;

        if (tokenAddr != address(0)) {
            IERC20 token = IERC20(tokenAddr);
            require(token.allowance(msg.sender, address(this)) >= money, "Token allowance fail");
            require(token.transferFrom(msg.sender, address(this), money), "Token transfer fail");
        } else {
            require(money <= msg.value, "Insufficient ETH");
        }

        emit Create(envelopId, p.createTime+ExpireDay, p.createTime+CloseoutDay);
        return envelopId;
    }

    function _random(uint256 remainMoney, uint remainCount) private view returns (uint256) {

       return uint256(keccak256(abi.encode(block.timestamp + block.difficulty + block.number))) % (remainMoney / remainCount * 2) + 1;
    }

    function _cal_random_amount(uint256 remainMoney, uint remainCount) private view returns (uint256) {

        uint256 amount = 0;
        if (remainCount == 1) {
            amount = remainMoney;
        } else if (remainCount == remainMoney) {
            amount = 1;
        } else if (remainCount < remainMoney) {
            amount = _random(remainMoney, remainCount);
        }
        return amount;
    }

    function _send(address tokenAddr, address payable to, uint256 amount) private {

        if (tokenAddr == address(0)) {
            require(to.send(amount), "Transfer ETH failed");
        } else {
            require(IERC20(tokenAddr).transfer(to, amount), "Transfer Token failed");
        }
    }

    function open(uint256 redEnvelopId) external returns (uint256) {

        require(redEnvelopInfos[redEnvelopId].creator != address(0), "Invalid ID");
        require(block.timestamp < redEnvelopInfos[redEnvelopId].createTime + ExpireDay, "Expired");
        require(redEnvelopInfos[redEnvelopId].remainCount > 0, "No share left");
        require(redEnvelopInfos[redEnvelopId].recipientInfos[msg.sender] == 0, "Already opened");

        if (!redEnvelopInfos[redEnvelopId].isPublic) {
            require(redEnvelopInfos[redEnvelopId].candidates[msg.sender], "Invalid candidate");
        }

        uint256 amount = _cal_random_amount(redEnvelopInfos[redEnvelopId].remainMoney, redEnvelopInfos[redEnvelopId].remainCount);

        redEnvelopInfos[redEnvelopId].remainMoney = redEnvelopInfos[redEnvelopId].remainMoney - amount;
        redEnvelopInfos[redEnvelopId].remainCount = redEnvelopInfos[redEnvelopId].remainCount - 1;
        redEnvelopInfos[redEnvelopId].recipientInfos[msg.sender] = amount;

        _send(redEnvelopInfos[redEnvelopId].tokenAddr, payable(msg.sender), amount);

        if (IERC20(mambaCoinAddr).balanceOf(address(this)) >= BonusMamb + BonusMamb) {
            require(IERC20(mambaCoinAddr).transfer(msg.sender, BonusMamb), "Transfer MAMB failed");
            require(IERC20(mambaCoinAddr).transfer(redEnvelopInfos[redEnvelopId].creator, BonusMamb), "Transfer MAMB failed");
        }

        emit Open(redEnvelopId, amount, redEnvelopInfos[redEnvelopId].remainMoney, redEnvelopInfos[redEnvelopId].remainCount);
        return amount;
    }

    function luckydraw(uint256 redEnvelopId) external returns (uint256) {

        require(redEnvelopInfos[redEnvelopId].creator != address(0), "Invalid ID");
        require(block.timestamp > redEnvelopInfos[redEnvelopId].createTime + ExpireDay, "Not expired");
        require(redEnvelopInfos[redEnvelopId].remainCount > 0, "No share left");
        require(redEnvelopInfos[redEnvelopId].luckydrawInfos[msg.sender] == 0, "Already luckydrew");

        require(IERC20(mambaCoinAddr).allowance(msg.sender, address(this)) >= LuckyDrawMamb, "Require 24 MAMB");

        uint256 amount = _cal_random_amount(redEnvelopInfos[redEnvelopId].remainMoney, redEnvelopInfos[redEnvelopId].remainCount);

        redEnvelopInfos[redEnvelopId].remainMoney = redEnvelopInfos[redEnvelopId].remainMoney - amount;
        redEnvelopInfos[redEnvelopId].remainCount = redEnvelopInfos[redEnvelopId].remainCount - 1;
        redEnvelopInfos[redEnvelopId].luckydrawInfos[msg.sender] = amount;

        _send(redEnvelopInfos[redEnvelopId].tokenAddr, payable(msg.sender), amount);

        require(IERC20(mambaCoinAddr).transferFrom(msg.sender, address(this), LuckyDrawMamb), "Insufficient MAMB");

        emit LuckyDraw(redEnvelopId, amount, redEnvelopInfos[redEnvelopId].remainMoney, redEnvelopInfos[redEnvelopId].remainCount);

        return amount;
    }

    function drawback(uint256 redEnvelopId) external returns (uint256) {

        require(redEnvelopInfos[redEnvelopId].creator != address(0), "Invalid ID");
        require(block.timestamp > redEnvelopInfos[redEnvelopId].createTime + ExpireDay, "Not expired");
        require(msg.sender == redEnvelopInfos[redEnvelopId].creator, "Not creator");
        require(redEnvelopInfos[redEnvelopId].remainMoney > 0, "No money left");

        uint256 amount = redEnvelopInfos[redEnvelopId].remainMoney;
        redEnvelopInfos[redEnvelopId].remainMoney = 0;
        redEnvelopInfos[redEnvelopId].remainCount = 0;

        _send(redEnvelopInfos[redEnvelopId].tokenAddr, payable(msg.sender), amount);

        emit DrawBack(redEnvelopId, amount);
        return amount;
    }

    function closeout(uint256 redEnvelopId) external returns (uint256) {

        require(redEnvelopInfos[redEnvelopId].creator != address(0), "Invalid ID");
        require(block.timestamp > redEnvelopInfos[redEnvelopId].createTime + CloseoutDay, "Not closed");
        require(msg.sender == owner, "Not contract owner");
        require(redEnvelopInfos[redEnvelopId].remainMoney > 0, "No money left");

        uint256 amount = redEnvelopInfos[redEnvelopId].remainMoney;
        redEnvelopInfos[redEnvelopId].remainMoney = 0;
        redEnvelopInfos[redEnvelopId].remainCount = 0;

        _send(redEnvelopInfos[redEnvelopId].tokenAddr, owner, amount);

        emit CloseOut(redEnvelopId, amount);
        return amount;
    }

    function get_info(uint256 redEnvelopId) external view returns (address, address, uint256, uint256, uint16, uint16, bool, uint, uint) {

        RedEnvelopInfo storage redEnvelopInfo = redEnvelopInfos[redEnvelopId];
        return (
        redEnvelopInfo.creator,
        redEnvelopInfo.tokenAddr,
        redEnvelopInfo.money,
        redEnvelopInfo.remainMoney,
        redEnvelopInfo.count,
        redEnvelopInfo.remainCount,
        redEnvelopInfo.isPublic,
        redEnvelopInfo.createTime + ExpireDay,
        redEnvelopInfo.createTime + CloseoutDay)
        ;
    }

    function record(uint256 redEnvelopId, address candidate) external view returns (bool, uint256, uint256) {

        return (
        redEnvelopInfos[redEnvelopId].candidates[candidate],
        redEnvelopInfos[redEnvelopId].recipientInfos[candidate],
        redEnvelopInfos[redEnvelopId].luckydrawInfos[candidate]
        );
    }
}