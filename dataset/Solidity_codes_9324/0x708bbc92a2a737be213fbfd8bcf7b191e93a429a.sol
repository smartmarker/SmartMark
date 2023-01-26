pragma solidity ^0.8.0;

library DateString {

    uint256 public constant SECONDS_PER_DAY = 24 * 60 * 60;
    uint256 public constant SECONDS_PER_HOUR = 60 * 60;
    uint256 public constant SECONDS_PER_MINUTE = 60;
    int256 public constant OFFSET19700101 = 2440588;

    function _daysToDate(uint256 _days)
        internal
        pure
        returns (
            uint256 year,
            uint256 month,
            uint256 day
        )
    {

        int256 __days = int256(_days);
        int256 L = __days + 68569 + OFFSET19700101;
        int256 N = (4 * L) / 146097;
        L = L - (146097 * N + 3) / 4;
        int256 _year = (4000 * (L + 1)) / 1461001;
        L = L - (1461 * _year) / 4 + 31;
        int256 _month = (80 * L) / 2447;
        int256 _day = L - (2447 * _month) / 80;
        L = _month / 11;
        _month = _month + 2 - 12 * L;
        _year = 100 * (N - 49) + _year + L;

        year = uint256(_year);
        month = uint256(_month);
        day = uint256(_day);
    }

    function encodeAndWriteTimestamp(
        string memory _prefix,
        uint256 _timestamp,
        string storage _output
    ) external {

        _encodeAndWriteTimestamp(_prefix, _timestamp, _output);
    }

    function _encodeAndWriteTimestamp(
        string memory _prefix,
        uint256 _timestamp,
        string storage _output
    ) internal {

        bytes memory bytePrefix = bytes(_prefix);
        bytes storage bytesOutput = bytes(_output);
        for (uint256 i = 0; i < bytePrefix.length; i++) {
            bytesOutput.push(bytePrefix[i]);
        }
        bytesOutput.push(bytes1("-"));
        timestampToDateString(_timestamp, _output);
    }

    function timestampToDateString(
        uint256 _timestamp,
        string storage _outputPointer
    ) public {

        _timestampToDateString(_timestamp, _outputPointer);
    }

    function _timestampToDateString(
        uint256 _timestamp,
        string storage _outputPointer
    ) internal {

        bytes storage output = bytes(_outputPointer);
        (uint256 year, uint256 month, uint256 day) = _daysToDate(
            _timestamp / SECONDS_PER_DAY
        );
        {
            uint256 firstDigit = day / 10;
            output.push(bytes1(uint8(bytes1("0")) + uint8(firstDigit)));
            uint256 secondDigit = day % 10;
            output.push(bytes1(uint8(bytes1("0")) + uint8(secondDigit)));
        }
        if (month == 1) {
            stringPush(output, "J", "A", "N");
        } else if (month == 2) {
            stringPush(output, "F", "E", "B");
        } else if (month == 3) {
            stringPush(output, "M", "A", "R");
        } else if (month == 4) {
            stringPush(output, "A", "P", "R");
        } else if (month == 5) {
            stringPush(output, "M", "A", "Y");
        } else if (month == 6) {
            stringPush(output, "J", "U", "N");
        } else if (month == 7) {
            stringPush(output, "J", "U", "L");
        } else if (month == 8) {
            stringPush(output, "A", "U", "G");
        } else if (month == 9) {
            stringPush(output, "S", "E", "P");
        } else if (month == 10) {
            stringPush(output, "O", "C", "T");
        } else if (month == 11) {
            stringPush(output, "N", "O", "V");
        } else if (month == 12) {
            stringPush(output, "D", "E", "C");
        } else {
            revert("date decoding error");
        }
        {
            uint256 lastDigits = year % 100;
            uint256 firstDigit = lastDigits / 10;
            output.push(bytes1(uint8(bytes1("0")) + uint8(firstDigit)));
            uint256 secondDigit = lastDigits % 10;
            output.push(bytes1(uint8(bytes1("0")) + uint8(secondDigit)));
        }
    }

    function stringPush(
        bytes storage output,
        bytes1 data1,
        bytes1 data2,
        bytes1 data3
    ) internal {

        output.push(data1);
        output.push(data2);
        output.push(data3);
    }
}