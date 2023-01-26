
pragma solidity ^0.5.16;

pragma experimental ABIEncoderV2;

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
}

contract Context {

    constructor () internal { }

    function _msgSender() internal view returns (address payable) {

        return msg.sender;
    }

    function _msgData() internal view returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

contract Ownable is Context {

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

        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }

    function isOwner() public view returns (bool) {

        return _msgSender() == _owner;
    }

    function renounceOwnership() public onlyOwner {

        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public onlyOwner {

        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {

        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}


contract ERC20{

    function transfer(address recipient, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    function approve(address spender, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

}

contract HEX4{

    function distribute(uint256 _amount) public;

}

contract Treasury{

     function transfer(address to, uint256 amount) external returns(bool);

}

contract RandomNumberGenerator{

     function generateRandomNumber(uint256 maxValue) public returns(uint256);

}

contract HexLotto is Ownable{


    using SafeMath for uint256;

    struct Entry {
        uint256 ticketNumber;
        uint256 tickets;
        uint256 hexAmount;
        address buyer;
        address ref;
    }

    struct PlayerStats {
        uint256 totalAmount;
        uint256 totalTickets;
        uint256 amountWon;
        uint256 bonusWithdrawalTickets;
        uint256 bonusAmount;
    }

    mapping(bytes32 => uint8) validQueryIds;
    mapping(address => PlayerStats) public playerStats;

    uint256 public totalAmount;
    uint256 public totalTickets;
    uint256 public ticketPrice;
    uint256 public minimumPotAmount;
    uint256 public minimumParticipants;
    uint256 public bonusTicketsWithdrawn;
    uint256 nonce;

    uint256 public lastWinnerId;

    address token;
    address hex4;
    address treasuryContract;
    address randomGenerationContract;
    address donatorWallet;
    address devWallet;
    address devWallet2;
    address devWallet3;
    address devWallet4;
    address devWallet5;

    address[] public players;

    uint256 public hourlyPot;
    uint256 public monthlyPot;
    uint256 public yearlyPot;
    uint256 public threeYearlyPot;

    uint256 public hourlyTickets;
    uint256 public monthlyTickets;
    uint256 public yearlyTickets;
    uint256 public threeYearlyTickets;

    uint256 public hex4amount;

    uint256 public lastHourly = now;
    uint256 public lastMonthly = now;
    uint256 public lastYearly = now;
    uint256 public lastThreeYearly = now;

    uint256 hour = 3600;
    uint256 day = hour * 24;
    uint256 month = day * 30;
    uint256 threeHundredDays = day * 300;
    uint256 threeYears = 31556926 * 3;

    Entry[] public hourlyParticipants;
    Entry[] public monthlyParticipants;
    Entry[] public yearlyParticipants;
    Entry[] public threeYearlyParticipants;

    event Enter(
        address indexed from,
        uint amount,
        address ref
    );

    event Won(
        address indexed player,
        uint amount
    );

    event Withdrawn(
        address indexed player,
        uint amount
    );

    modifier isTreasurySet() {

        require(treasuryContract != address(0), "Treasury contract isn't set");
        _;
    }

    modifier isRandomNumberSet() {

        require(randomGenerationContract != address(0), "Random generator contract contract isn't set");
        _;
    }

    constructor() public {
        token = address(0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39);
        hex4 = address(0xd52dca990CFC3760e0Cb0A60D96BE0da43fEbf19);
        donatorWallet = address(0x723e82Eb1A1b419Fb36e9bD65E50A979cd13d341);
        devWallet = address(0x35e9034f47cc00b8A9b555fC1FDB9598b2c245fD);
        devWallet2 = address(0xB1A7Fe276cA916d8e7349Fa78ef805F64705331E);
        devWallet3 = address(0xbf1984B12878c6A25f0921535c76C05a60bdEf39);
        devWallet4 = address(0xD30BC4859A79852157211E6db19dE159673a67E2);
        devWallet5 = address(0xe551072153c02fa33d4903CAb0435Fb86F1a80cb);
        nonce = 1;
        minimumParticipants = 3;
        ticketPrice = 500000000000; //default ticket price 5000 HEX
        minimumPotAmount = 2550000000000; //default min pot amount 25500 HEX

        hourlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));
        monthlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));
        yearlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));
        threeYearlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));
    }

    function setTreasury(address newTreasuryContract) public onlyOwner{

        require(newTreasuryContract != address(0), "New treasury is the 0 address");
        treasuryContract = newTreasuryContract;
    }
    
    function setRandomGenerator(address newRandomGenerator) public onlyOwner {

        require(newRandomGenerator != address(0), "New random generator contract is the 0 address");
        randomGenerationContract = newRandomGenerator;
    }
    
    function setTicketPrice(uint256 amount) public onlyOwner{

        require(amount > 0, "amount must be greater than 0");
        ticketPrice = amount;
    }

    function setMinimumPot(uint256 amount) public onlyOwner{

        require(amount > 0, "amount must be greater than 0");
        minimumPotAmount = amount;
    }

    function getHourlyParticipants() public view returns(Entry[] memory) {

        return hourlyParticipants;
    }

    function getMonthlyParticipants() public view returns(Entry[] memory) {

        return monthlyParticipants;
    }

    function getYearlyParticipants() public view returns(Entry[] memory) {

        return yearlyParticipants;
    }

    function getThreeYearlyParticipants() public view returns(Entry[] memory) {

        return threeYearlyParticipants;
    }

    function getPlayers() public view returns(address[] memory) {

        return players;
    }

    function distributeToHex4() public {

        HEX4(hex4).distribute(hex4amount);
        hex4amount = 0;
    }

    function distribute(uint256 quantity, uint256 tickets, address ref) private {

        uint256[7] memory quantities;

        quantities[0] = quantity.mul(69).div(100); //Hourly
        quantities[1] = quantity.mul(10).div(100); //Monthly
        quantities[2] = quantity.mul(4).div(100); //300 days
        quantities[3] = quantity.mul(1).div(100); //3 yearly
        quantities[4] = quantity.mul(10).div(100); //Dev
        quantities[5] = quantity.mul(1).div(100); //Hex4
        quantities[6] = quantity.mul(5).div(100); //Treasury

        require(ERC20(token).transfer(treasuryContract, quantities[6]), "send to treasury failed");

        hex4amount += quantities[5];
        require(ERC20(token).approve(hex4, hex4amount), "approve hex failed");

        require(ERC20(token).transfer(donatorWallet, quantities[4].div(6)), 'send to donator failed');
        require(ERC20(token).transfer(devWallet, quantities[4].div(6)), 'send to dev failed');
        require(ERC20(token).transfer(devWallet2, quantities[4].div(6)), 'send to dev2 failed');
        require(ERC20(token).transfer(devWallet3, quantities[4].div(6)), 'send to dev3 failed');
        require(ERC20(token).transfer(devWallet4, quantities[4].div(6)), 'send to dev4 failed');
        require(ERC20(token).transfer(devWallet5, quantities[4].div(6)), 'send to dev5 failed');

        hourlyPot += quantities[0];
        monthlyPot += quantities[1];
        yearlyPot += quantities[2];
        threeYearlyPot += quantities[3];

        saveEntries(tickets, quantities[0], quantities[1], quantities[2], quantities[3], ref);
    }

    function entry (uint256 tickets, address ref) public isTreasurySet{

        uint256 quantity = ticketPrice.mul(tickets);

        uint256 userBalance = ERC20(token).balanceOf(msg.sender);

        require(userBalance >= quantity, "Not enough HEX tokens in balance.");

        require(ERC20(token).transferFrom(msg.sender, address(this), quantity), "Transfer failed.");

        distribute(quantity, tickets, ref);

        playerStats[msg.sender].totalAmount += quantity;
        playerStats[msg.sender].totalTickets += tickets;

        totalTickets += tickets;
        totalAmount += quantity;
        emit Enter(msg.sender, quantity, ref);
     }

    function saveEntries(
        uint256 tickets, 
        uint256 hourly, 
        uint256 monthly, 
        uint256 yearly, 
        uint256 threeYearly, 
        address ref
    ) 
        private 
    {

        Entry memory hourlyEntry = Entry(hourlyTickets + tickets, tickets, hourly, msg.sender, ref);
        Entry memory monthlyEntry = Entry(monthlyTickets + tickets, tickets, monthly, msg.sender, ref);
        Entry memory yearlyEntry = Entry(yearlyTickets + tickets, tickets, yearly, msg.sender, ref);
        Entry memory threeYearlyEntry = Entry(threeYearlyTickets + tickets, tickets, threeYearly, msg.sender, ref);

        hourlyParticipants.push(hourlyEntry);
        monthlyParticipants.push(monthlyEntry);
        yearlyParticipants.push(yearlyEntry);
        threeYearlyParticipants.push(threeYearlyEntry);

        hourlyTickets += tickets;
        monthlyTickets += tickets;
        yearlyTickets += tickets;
        threeYearlyTickets += tickets;

        players.push(msg.sender);
    }

    function getTreasuryBalance() public view isTreasurySet returns(uint256)  {

         return ERC20(token).balanceOf(treasuryContract);
    }

    function getAvailableBonusTickets(address player) public view returns(uint256){


        if(playerStats[player].totalTickets == 0) {
            return 0;
        }
        
        return playerStats[player].totalTickets - playerStats[player].bonusWithdrawalTickets;
    }

    function getAvailableBonusAmount(address player) public view returns(uint256){


        uint256 playerAvailable = getAvailableBonusTickets(player);
        uint256 totalAvailable = totalTickets.sub(bonusTicketsWithdrawn);

        if(playerAvailable == 0 || totalAvailable == 0) {
            return 0;
        }
        
        return getTreasuryBalance().mul(playerAvailable).div(totalAvailable);
    }

    function withdraw() public isTreasurySet {

        require(totalTickets > bonusTicketsWithdrawn, "No bonus available to withdraw");
        uint256 amount = getAvailableBonusAmount(msg.sender);
        require(amount > 0, "No bonus available");
        require(Treasury(treasuryContract).transfer(msg.sender, amount), "Withdrawal failed");
        
        bonusTicketsWithdrawn += (playerStats[msg.sender].totalTickets - playerStats[msg.sender].bonusWithdrawalTickets);
        playerStats[msg.sender].bonusWithdrawalTickets = playerStats[msg.sender].totalTickets;
        playerStats[msg.sender].bonusAmount += amount;

        emit Withdrawn(msg.sender, amount);
    }

    function finishHourly() external isRandomNumberSet{

        require(now > lastHourly.add(hour), "Can only finish game once per hour.");
        require(hourlyParticipants.length >= minimumParticipants, "Needs to meet minimum participants");
        require(hourlyPot > minimumPotAmount, "Hourly pot needs to be higher before game can finish");
        
        uint256 winningTicketNumber = RandomNumberGenerator(randomGenerationContract).generateRandomNumber(hourlyTickets);

        pickHourlyWinner(winningTicketNumber);
    }

    function pickHourlyWinner(uint256 random) private {

        uint256 randomWinner = random % (hourlyTickets - 1);
        lastWinnerId = randomWinner;

        address[2] memory winner = pickWinner(hourlyParticipants, randomWinner);
        address hourlyWinner = winner[0];//buyer address
        address winnerRef = winner[1];//ref address
        require(hourlyWinner != address(0), "Can not send to 0 address");
        uint winnings;
        if(winnerRef == address(0)){
            winnings = hourlyPot;
        }
        else{
            uint refWinnings = hourlyPot.div(20);//5% of winning to ref
            winnings = hourlyPot.sub(refWinnings);
            require(ERC20(token).transfer(winnerRef, refWinnings), "ref transfer failed");
        }
       
        playerStats[hourlyWinner].amountWon += hourlyPot;

        lastHourly = now;
        hourlyPot = 0;
        hourlyTickets = 0;
        delete hourlyParticipants;
        hourlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));

        emit Won(hourlyWinner, winnings);

        require(ERC20(token).transfer(hourlyWinner, winnings), "transfer failed");
     }
     
  
    function finishMonthly() external isRandomNumberSet{

        require(now > lastMonthly.add(month), "Can only finish game once per month.");
        require(monthlyParticipants.length >= minimumParticipants, "Needs to meet minimum participants");
        require(monthlyPot > minimumPotAmount, "Monthly pot needs to be higher before game can finish");

         uint256 winningTicketNumber = RandomNumberGenerator(randomGenerationContract).generateRandomNumber(monthlyTickets);

        pickMonthlyWinner(winningTicketNumber);
    }

    function pickMonthlyWinner(uint256 random) private {

        uint256 randomWinner = random % (monthlyTickets - 1);
        lastWinnerId = randomWinner;

        address[2] memory winner = pickWinner(monthlyParticipants, randomWinner);
        address monthlyWinner = winner[0];//buyer address
        address winnerRef = winner[1];//ref address
        require(monthlyWinner != address(0), "Can not send to 0 address");
        uint winnings;
        if(winnerRef == address(0)){
            winnings = monthlyPot;
        }
        else{
            uint refWinnings = monthlyPot.div(20);//5% of winning to ref
            winnings = monthlyPot.sub(refWinnings);
            require(ERC20(token).transfer(winnerRef, refWinnings), "ref transfer failed");
        }
       
        playerStats[monthlyWinner].amountWon += monthlyPot;

        lastMonthly = now;
        monthlyPot = 0;
        monthlyTickets = 0;
        delete monthlyParticipants;
        monthlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));

        emit Won(monthlyWinner, winnings);

        require(ERC20(token).transfer(monthlyWinner, winnings), "transfer failed");
     }

    function finishYearly() external isRandomNumberSet{

        require(now > lastYearly.add(threeHundredDays), "Can only finish game once every 300 days.");
        require(yearlyParticipants.length >= minimumParticipants, "Needs to meet minimum participants");
        require(yearlyPot > minimumPotAmount, "Yearly pot needs to be higher before game can finish");

        uint256 winningTicketNumber = RandomNumberGenerator(randomGenerationContract).generateRandomNumber(yearlyTickets);
        pickYearlyWinner(winningTicketNumber);
    }

    function pickYearlyWinner(uint256 random) private {

        uint256 randomWinner = random % (yearlyTickets - 1);
        lastWinnerId = randomWinner;

        address[2] memory winner = pickWinner(yearlyParticipants, randomWinner);
        address yearlyWinner = winner[0];//buyer address
        address winnerRef = winner[1];//ref address
        require(yearlyWinner != address(0), "Can not send to 0 address");
        uint winnings;
        if(winnerRef == address(0)){
            winnings = yearlyPot;
        }
        else{
            uint refWinnings = yearlyPot.div(20);//5% of winning to ref
            winnings = yearlyPot.sub(refWinnings);
            require(ERC20(token).transfer(winnerRef, refWinnings), "ref transfer failed");
        }

        playerStats[yearlyWinner].amountWon += yearlyPot;

        lastYearly = now;
        yearlyPot = 0;
        yearlyTickets = 0;
        delete yearlyParticipants;
        yearlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));

        emit Won(yearlyWinner, winnings);

        require(ERC20(token).transfer(yearlyWinner, winnings), "transfer failed");
     }

    function finishThreeYearly() external isRandomNumberSet {

        require(now > lastThreeYearly.add(threeYears),  "Can only finish game every three years.");
        require(threeYearlyParticipants.length >= minimumParticipants, "Needs to meet minimum participants");
        require(threeYearlyPot >  minimumPotAmount, "3 yearly pot needs to be higher before game can finish");

        uint256 winningTicketNumber = RandomNumberGenerator(randomGenerationContract).generateRandomNumber(threeYearlyTickets);
        
        pickThreeYearlyWinner(winningTicketNumber);
    }

    function pickThreeYearlyWinner(uint256 random) private {

        uint256 randomWinner = random % (threeYearlyTickets - 1);
        lastWinnerId = randomWinner;

        address[2] memory winner = pickWinner(threeYearlyParticipants, randomWinner);
        address threeYearlyWinner = winner[0];//buyer address
        address winnerRef = winner[1];//ref address
        require(threeYearlyWinner != address(0), "Can not send to 0 address");
        uint winnings;
        if(winnerRef == address(0)){
            winnings = threeYearlyPot;
        }
        else{
            uint refWinnings = threeYearlyPot.div(20);//5% of winning to ref
            winnings = threeYearlyPot.sub(refWinnings);
            require(ERC20(token).transfer(winnerRef, refWinnings), "ref transfer failed");
        }
       
        playerStats[threeYearlyWinner].amountWon += threeYearlyPot;

        lastThreeYearly = now;
        threeYearlyPot = 0;
        threeYearlyTickets = 0;
        delete threeYearlyParticipants;
        threeYearlyParticipants.push(Entry(0, 0, 0, address(0), address(0)));

        emit Won(threeYearlyWinner, winnings);

        require(ERC20(token).transfer(threeYearlyWinner, winnings), "transfer failed");
     }

    function pickWinner(Entry[] memory entries, uint256 random) internal pure returns(address[2] memory) {


        address winner;
        address ref;
        uint256 left = 0;
        uint256 right = entries.length-1;
        uint256 middle;

        while(left <= right){
          middle = (left+right) >> 1; // floor((left + right) / 2)
          if(middle == 0){
            require(false, "Sentinel value, no valid winner");
          }
          uint256 ticket = entries[middle].ticketNumber;
          if (ticket < random) {
            left = middle + 1;
          } else {
            if(entries[middle-1].ticketNumber >= random) {
              right = middle - 1;
            } else {
              winner = entries[middle].buyer;
              ref = entries[middle].ref;
              break;
            }
          }
        }
        return ([winner, ref]);
     }
}