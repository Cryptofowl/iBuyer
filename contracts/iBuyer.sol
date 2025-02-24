// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.16;

import "https://github.com/UMAprotocol/protocol/blob/7a93650a7494eaee83756382a18ecf11314499cf/packages/core/contracts/optimistic-oracle-v3/interfaces/OptimisticOracleV3Interface.sol";

contract iBuyer is Iibuyer {

    // Need to map assertion statement to stored deal details so the assertion bool can greenlight

    bytes32 public immutable openingPacketRules;// = 0x4435c47b89eee270a3cddee3980eaac170eb991f7952b1ff4769ca18419ffc8a;
    bytes32 public immutable closingPacketRules;// = 0x4435c47b89eee270a3cddee3980eaac170eb991f7952b1ff4769ca18419ffc8a;
    bytes32 public immutable assertionStatement = "Matches the rules at ipfs:";

    mapping (address => Deal[]) public deals; // Why not map by assertion id? 
    // Main issue would be asserters other than the agent creating the closing deal parameters
    // i.e settle and release funding for opening after the challenge period, then immediately close with invalid parameters
    // Can the closing parameters be overwritten as necessary? 
    // Can the closing terms change before the challenge period ends? No, docs are signed
    // Can add the originator as the authorized address in the deal struct

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

        uint256 value = deal.authorizedFunding;
        deal.authorizedFunding = 0;

        (bool success, ) = deal.escrowAddress.call{value: value}("");
        require(success, "The transfer could not be completed."); 
        
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
                uint256 value = deal.requestedFunding;
                deal.requestedFunding = 0;
                deal.authorizedFunding = 0;
                (bool success, ) = deal.escrowAddress.call{value: value}("");
                require(success, "The transfer could not be completed."); 
            }
        } else if (!deal.settledClose) {
            if (settleAndGetAssertionResult(deal.closingId)) {
                deal.settledClose = true;
                uint256 value = deal.requestedFunding;
                deal.requestedFunding = 0;
                deal.authorizedFunding = 0;
                (bool success, ) = deal.escrowAddress.call{value: value}("");
                require(success, "The transfer could not be completed."); 
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

        require(deal.openingId > 0, "Deal does not exist.");
        require(deal.settledOpen, "Opening packet has not been settled yet");
        require(deal.authorizedFunding == 0, "Remaining funding must be claimed");

        deals[msg.sender][_index].closingId =
        oov3.assertTruthWithDefaults(assertion, address(this));
        deals[msg.sender][_index].closingCID = _packetCID;

        bytes memory assertion = abi.encodePacked(_packetCID, assertionStatement, closingPacketRules);

        return deal;
    }

    function settleAndGetAssertionResult(bytes32 _assertionId) internal returns (bool) {
        // Needs to be able to update state for authorized funding amounts
        if (oov3.settleAndGetAssertionResult(_assertionId)) {
            
        }

        return oov3.settleAndGetAssertionResult(_assertionId);
    }

    function getAssertionResult(bytes32 _assertionId) public view returns (bool) {
        return oov3.getAssertionResult(_assertionId);
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