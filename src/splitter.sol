// SPDX-License-Identifier: GPLv3
pragma solidity ^0.8.16;

contract splitter {
    function split(bytes memory _input) public pure returns (bytes32[] memory) {
            bytes memory data = bytes(_input);
            uint256 length = data.length;
            bytes32[] memory output = new bytes32[](length);
            
            assembly {
                let dataPtr := add(data, 0x20)
                let resultPtr := add(output, 0x20)
                let endPtr := add(dataPtr, mload(data))
                for {} lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 0x01) resultPtr := add(resultPtr, 0x20) } {
                    mstore(resultPtr, shr(248, mload(dataPtr)))
                }
            }
            return output;
        }
}