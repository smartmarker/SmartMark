
pragma solidity ^0.4.25;

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

contract FomoBet  {

    using SafeMath for uint;
    struct bet {
        address maker;
        address taker;
        uint256 round;
        bool longOrShort;// false if maker bets round will end before - true if maker bets round will last longer then
        bool validated;
        uint256 betEnd; // ending time of bet 
        uint256 betSize; // winner gets this amount
        
        }
    struct offer {
        address maker;
        uint256 amount;
        bool longOrShort;// false if maker bets round will end before - true if maker bets round will last longer then
        uint256 betEndInDays; // ending time of bet 
        uint256 betSize; // maker gives this amount for each takersize
        uint256 takerSize; // for each offer taken taker gives this amount
        } 
    
    FoMo3Dlong constant FoMo3Dlong_ = FoMo3Dlong(0xA62142888ABa8370742bE823c1782D17A0389Da1);    
    mapping(uint256 => bet) public placedBets;
    uint256 public nextBetInLine;
    mapping(uint256 => offer) public OpenOffers;
    uint256 public nextBetOffer;
    mapping(address => uint256) public playerVault;
    function vaultToWallet() public {

        
        address sender = msg.sender;
        require(playerVault[sender] > 0);
        uint256 value = playerVault[sender];
        playerVault[sender] = 0;
        sender.transfer(value);
        
    }
    function () external payable{
        address sender= msg.sender;
        playerVault[sender] = playerVault[sender].add(msg.value);
    }
    function setupOffer(uint256 amountOffers, bool longOrShort, uint256 endingInDays, uint256 makerGive, uint256 takerGive) public payable{

        address sender = msg.sender;
        uint256 value = msg.value;
        require(value >= amountOffers.mul(makerGive));
        require(makerGive > 0);
        OpenOffers[nextBetOffer].maker = sender;
        OpenOffers[nextBetOffer].amount = amountOffers;
        OpenOffers[nextBetOffer].longOrShort = longOrShort;
        OpenOffers[nextBetOffer].betEndInDays = endingInDays;
        OpenOffers[nextBetOffer].betSize = makerGive;
        OpenOffers[nextBetOffer].takerSize = takerGive;
        
        nextBetOffer++;
    }
    function addToExistingOffer(uint256 offerNumber, uint256 amountOffers) public payable{

        address sender = msg.sender;
        uint256 value = msg.value;
        require(sender == OpenOffers[offerNumber].maker);
        require(value >= OpenOffers[offerNumber].betSize.mul(amountOffers));
        OpenOffers[offerNumber].amount = OpenOffers[offerNumber].amount.add(amountOffers);
    }
    function removeFromExistingOffer(uint256 offerNumber, uint256 amountOffers) public {

        address sender = msg.sender;
        
        require(sender == OpenOffers[offerNumber].maker);
        require(amountOffers <= OpenOffers[offerNumber].amount);
        OpenOffers[offerNumber].amount = OpenOffers[offerNumber].amount.sub(amountOffers);
        playerVault[sender] = playerVault[sender].add(amountOffers.mul(OpenOffers[offerNumber].betSize));
    }
    function takeOffer(uint256 offerNumber, uint256 amountOffers) public payable{

        address sender = msg.sender;
        uint256 value = msg.value;
        uint256 timer = now;
        
        require(amountOffers >= OpenOffers[offerNumber].amount );
        require(value >= amountOffers.mul(OpenOffers[offerNumber].takerSize));
        placedBets[nextBetOffer].longOrShort = OpenOffers[offerNumber].longOrShort;
        placedBets[nextBetOffer].maker = OpenOffers[offerNumber].maker;
        placedBets[nextBetOffer].taker = sender;
        uint256 timeframe = OpenOffers[offerNumber].betEndInDays * 1 days;
        placedBets[nextBetOffer].betEnd =  timer.add(timeframe);
        placedBets[nextBetOffer].round = FoMo3Dlong_.rID_();
        placedBets[nextBetOffer].betSize = value.add(amountOffers.mul(OpenOffers[offerNumber].betSize));
        OpenOffers[offerNumber].amount = OpenOffers[offerNumber].amount.sub(amountOffers);
        nextBetOffer++;
    }
    function validateBet(uint256 betNumber) public {

        
        (uint256 _end,bool _ended,uint256 _eth) = fomoroundInfo(placedBets[betNumber].round);
        uint256 timer = _end;
        
        if(placedBets[betNumber].validated == false){
            if(placedBets[betNumber].longOrShort == true){
                if(timer >= placedBets[betNumber].betEnd){
                    placedBets[betNumber].validated = true;
                    playerVault[placedBets[betNumber].maker] = playerVault[placedBets[betNumber].maker].add(placedBets[betNumber].betSize);
                }
                if(timer < placedBets[betNumber].betEnd && _ended == true){
                    placedBets[betNumber].validated = true;
                    playerVault[placedBets[betNumber].taker] = playerVault[placedBets[betNumber].taker].add(placedBets[betNumber].betSize);
                }
            }
            if(placedBets[betNumber].longOrShort == false){
                if(timer >= placedBets[betNumber].betEnd ){
                    placedBets[betNumber].validated = true;
                    playerVault[placedBets[betNumber].taker] = playerVault[placedBets[betNumber].taker].add(placedBets[betNumber].betSize);
                }
                if(timer < placedBets[betNumber].betEnd &&  _ended == true){
                    placedBets[betNumber].validated = true;
                    playerVault[placedBets[betNumber].maker] = playerVault[placedBets[betNumber].maker].add(placedBets[betNumber].betSize);
                }
            }
        }
    }
    function death () external {
        require(msg.sender == 0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220);
    selfdestruct(0x0B0eFad4aE088a88fFDC50BCe5Fb63c6936b9220);
        
    }
    function getOfferInfo() public view returns(address[] memory _Owner, uint256[] memory locationData , bool[] memory allows){

          uint i;
          address[] memory _locationOwner = new address[](nextBetOffer);
          uint[] memory _locationData = new uint[](nextBetOffer*5); //Bonds + fills + vault + reinvest + divs + offernumber
          bool[] memory _locationData2 = new bool[](nextBetOffer); //isAlive
          uint y;
          for(uint x = 0; x < nextBetOffer; x+=1){
            
             
                _locationOwner[i] = OpenOffers[i].maker;
                _locationData[y] = OpenOffers[i].amount;
                _locationData[y+1] = OpenOffers[i].betEndInDays;
                _locationData[y+2] = OpenOffers[i].betSize;
                _locationData[y+3] = OpenOffers[i].takerSize;
                _locationData[y+4] = x;// offernumber
                _locationData2[i] = OpenOffers[i].longOrShort;
              y += 5;
              i+=1;
            }
          
          return (_locationOwner,_locationData, _locationData2);
        }
        function getbetsInfo() public view returns(address[] memory _Owner, uint256[] memory locationData , bool[] memory allows){

          uint i;
          address[] memory _locationOwner = new address[](nextBetOffer*2);
          uint[] memory _locationData = new uint[](nextBetOffer*3); //Bonds + fills + vault + reinvest + divs
          bool[] memory _locationData2 = new bool[](nextBetOffer*2); //isAlive
          uint y;
          for(uint x = 0; x < nextBetOffer; x+=1){
            
             
                _locationOwner[i] = placedBets[i].maker;
                _locationOwner[i+1] = placedBets[i].taker;
                _locationData[y] = placedBets[i].round;
                _locationData[y+1] = placedBets[i].betEnd;
                _locationData[y+2] = placedBets[i].betSize;
                _locationData2[i] = placedBets[i].validated;
                _locationData2[i+1] = placedBets[i].longOrShort;
              y += 3;
              i+=2;
            }
          
          return (_locationOwner,_locationData, _locationData2);
        }
        function fomoround () public view returns(uint256 roundNumber){
            uint256 round = FoMo3Dlong_.rID_();
            return(round);
        }//FoMo3Dlong_.rID_();
        function fomoroundInfo (uint256 roundNumber) public view returns(uint256 _end,bool _ended,uint256 _eth){
           plyr = roundNumber;
            
            (uint256 plyr,uint256 team,uint256 end,bool ended,uint256 strt,uint256 keys,uint256 eth,uint256 pot,uint256 mask,uint256 ico,uint256 icoGen,uint256 icoAvg) = FoMo3Dlong_.round_(plyr);
            return( end, ended, eth);
        }
}
interface FoMo3Dlong {

    
    function rID_() external view returns(uint256);

    function round_(uint256) external view returns(uint256 plyr,uint256 team,uint256 end,bool ended,uint256 strt,uint256 keys,uint256 eth,uint256 pot,uint256 mask,uint256 ico,uint256 icoGen,uint256 icoAvg);

    
}