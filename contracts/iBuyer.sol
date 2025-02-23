// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.20;

import "./OptimisticOracleV3Interface.sol";

contract iBuyer {

    struct Deal {
        bytes32 openingId;
        bytes32 closingId;
        bytes32 openingCID;
        bytes32 closingCID;
        bytes32[] supportingDocuments;
        bytes32 escrowDetails;
        address escrowAddress;
        uint16  agentId;
        uint256 expiration;
        uint256 authorizedFunding;
        bool settledOpen;
        bool settledClose;
    }

    // Need to map assertion statement to stored deal details so the assertion bool can greenlight

    bytes32 public immutable openingPacketRules;// = 0x4435c47b89eee270a3cddee3980eaac170eb991f7952b1ff4769ca18419ffc8a;
    bytes32 public immutable closingPacketRules;// = 0x4435c47b89eee270a3cddee3980eaac170eb991f7952b1ff4769ca18419ffc8a;
    bytes32 public immutable assertionStatement = "Matches the rules at ipfs:";
    mapping (address => Deal[]) public deals;
    mapping (bytes slice => uint8) public selectors;
    OptimisticOracleV3Interface oov3 = 
        OptimisticOracleV3Interface(0x9923D42eF695B5dd9911D05Ac944d4cAca3c4EAB);

    constructor (bytes32 _openingRules, bytes32 _closingRules) {
        openingPacketRules = _openingRules;
        closingPacketRules = _closingRules;
    }
    function releaseFunding(uint32 _index) public returns (bool, uint256) {
        Deal storage deal = deals[msg.sender][_index];

        require(deal.openingId > 0, "Deal does not exist.");
        require(deal.expiration >= block.timestamp, "This deal has expired.");
        require(deal.settledOpen || deal.settledClose, "Oracle assertion has not been settled");
        require(deal.authorizedFunding > 0, "Funds have not been authorized");

        if (deal.authorizedFunding > 0) {
            (bool success, ) = deal.escrowAddress.call{value: deal.authorizedFunding}("");
            require(success, "The transfer could not be completed."); 
        }
        
        /*
           Checks: is the caller wallet allowed to withdraw? 
           has an opening/closing packet been asserted?
           What is the amount of funds allowed to be withdrawn for this stage of the deal?
           Has the deal expired? 
        */
    }

    function settleAndReleaseFunding(uint32 _index) public {
        Deal storage deal = deals[msg.sender][_index];

        require(deal.openingId > 0, "Deal does not exist.");
        require(deal.expiration >= block.timestamp, 'This deal has expired.');
        require(deal.settledOpen == false || deal.settledClose == false, "Deal has already been settled");

        // Settle packet
        if (!deal.settledOpen) {
            if (settleAndGetAssertionResult(deal.openingId)) {
                deal.settledOpen = true;
                (bool success, ) = deal.escrowAddress.call{value: deal.authorizedFunding}("");
                require(success, "The transfer could not be completed."); 
                deal.authorizedFunding = 0;
            }
        } else if (!deal.settledClose) {
            if (settleAndGetAssertionResult(deal.closingId)) {
                deal.settledClose = true;
                (bool success, ) = deal.escrowAddress.call{value: deal.authorizedFunding}("");
                require(success, "The transfer could not be completed."); 
                deal.authorizedFunding = 0;
            }
        }
    }

    function assertOpeningPacket(bytes calldata _packetCID, Deal calldata inputs) public {
        // Needs to store the assertionId -- map to address
        // Verify input hash
        bytes32 inputHash = keccak256(abi.encode(inputs));
        require(inputHash == _decodeCID(_packetCID), "Inputs do not match the uploaded packet");

        // Needs a challenge window of 24hrs+
        bytes memory assertion = abi.encodePacked(_packetCID, assertionStatement, closingPacketRules);
        deals[msg.sender][deals[msg.sender].length + 1].openingId = oov3.assertTruthWithDefaults(assertion, address(this));
        

        // Require that the CID == the encoded hash of the opening packet struct
        // CIDs are a massive pain to compute: <base><cid-version><multicodec><multihash(name-size-digest)>
        // So I've got to:
        // - Store a mapping of the hex value of each prefix
        // - Store reference to hash functions and their output length
        // - Store reference to encoding formats
        // - Extract the digest from the multihash and compare to input
        // - Figure out the struct encoding so that the input params == the formatted data on IPFS
        // Alternatively could have the packet rules specify a matching hash of the inputs... not as strong but technically stops the process from breaking
        // So probably needs to be a basic IPFS packet that only specifies contract inputs & contains reference to a secondary CID with supporting documents, therefore if the hash matches the inputs then UMA can filter for underwriting rules
        // Do I even need to decode the CID if all the inputs are stored on-chain?
        // Input validation ensures that the CID in the assertion statement matches the hash of the contract inputs
        // Alternatively UMA verifiers would be looking at the contract outputs directly, requires someone to run a front end, not ideal

        // deal.escrowDetails = _escrowDetails;
        // deal.escrowAddress = _escrowAddress;
        // deal.agentId = _agentId;
        // deal.expiration = _expiration;
        // deal.authorizedFunding = _authorizedFunding;
        // deal.settledOpen = true;
    }

    function assertClosingPacket(bytes32 _packetCID, uint32 _index, Deal calldata inputs) public returns (Deal memory) {
        Deal storage deal = deals[msg.sender][_index];

        require(deal.settledOpen, "Opening packet has not been settled yet");
        require(deal.authorizedFunding == 0, "Remaining funding must be claimed");

        bytes memory assertion = abi.encodePacked(_packetCID, assertionStatement, closingPacketRules);

        deals[msg.sender][_index].closingId =
            oov3.assertTruthWithDefaults(assertion, address(this));
        deals[msg.sender][_index].closingCID = _packetCID;
        return deal;
    }

    function settleAndGetAssertionResult(bytes32 _assertionId) internal returns (bool) {
        // Needs to be able to update state for authorized funding amounts
        return oov3.settleAndGetAssertionResult(_assertionId);
    }

    function getAssertionResult(bytes32 _assertionId) public view returns (bool) {
        return oov3.getAssertionResult(_assertionId);
    }

    function _decodeCID(bytes calldata CID) internal view returns (bytes32) {
        bytes memory decoded;
        bytes32 hash;
        // v0 CIDs will be 46 characters beginning with Qm
        if (keccak256(abi.encodePacked(CID[0:1])) == keccak256(abi.encodePacked("Qm")) && CID.length == 46) {
            // Decode as base58
            // QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR
            decoded = bytes("1220c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a");
            assembly {
                    hash := mload(add(decoded, 4))
                }
        } else {
            // Decode according to multibase spec
            // Use a mapping as a lookup table, map the bytes to function selector
            uint8 selector = selectors[CID[0:1]];
            if (CID[0] == "b") {
                // Base32 decoding
                // Go write a library I guess
                decoded = bytes("01701220c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a");
                assembly {
                    hash := mload(add(decoded, 8))
                }
                // Version: 01 Codec: 70 Multihash: 12 20 hash: 0xc3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a
            }
        } 
        return (hash);
    }

    function returnDataFormat(Deal calldata inputs) public pure returns (Deal memory, bytes32 hash, bytes memory encoding) {
        encoding = abi.encode(inputs);
        hash = keccak256(encoding);
        return (inputs, hash, abi.encode(inputs));
    }

}

interface IiBuyer {

    // Are ya ready kids? i i buyer 

    struct Deal {
        bytes32 openingId;
        bytes32 closingId;
        bytes32 openingCID;
        bytes32 closingCID;
        bytes32 escrowDetails;
        bytes32[] supportingDocuments;
        address escrowAddress;
        uint16  agentId;
        uint256 expiration;
        uint256 authorizedFunding;
        uint256 requestedFunding;
        bool settledOpen;
        bool settledClose;
    }

    struct packetInputs {
        bytes32 packetCID;
        bytes32 escrowDetails;
        bytes32[] supportingDocuments;
        address escrowAddress;
        uint16  agentId;
        uint256 authorizedFunding;
        uint256 requestedFunding;
    }

}