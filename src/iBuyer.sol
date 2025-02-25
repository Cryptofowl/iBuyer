// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.16;

import "./interfaces/OptimisticOracleV3Interface.sol";
import "./splitter.sol";
import "./verifier.sol";

interface IiBuyer {

    struct Deal {
        address originator;
        bytes32 openingId;
        bytes32 closingId;
        bytes openingCID;
        bytes closingCID;
        bytes32 escrowDetails;
        bytes[] openingDocuments;
        bytes[] closingDocuments;
        address escrowAddress;
        uint16  agentId;
        uint256 expiration;
        uint256 authorizedFunding;
        uint256 requestedFunding;
        bool settledOpen;
        bool settledClose;
    }

    struct PacketInputs {
        bytes32 packetCID;
        bytes32 escrowDetails;
        bytes[] supportingDocuments;
        address escrowAddress;
        uint16  agentId;
        uint256 authorizedFunding;
        uint256 requestedFunding;
        uint256 expiration;
    }

}

contract iBuyer is IiBuyer, splitter {

    // Need to map assertion statement to stored deal details so the assertion bool can greenlight

    bytes32 public immutable openingPacketRules; // CID containing corresponding rules for opening packet assertions
    bytes32 public immutable closingPacketRules; // CID containing corresponding rules for closing packet assertions
    bytes32 public immutable assertionStatement = "Matches the rules at ipfs:";
    uint256 public immutable maxExpiration; // Maximum duration before a deal expires
    UltraVerifier public immutable verifier; 

    mapping (bytes32 => Deal) public deals;

    OptimisticOracleV3Interface oov3 = 
        OptimisticOracleV3Interface(0x9923D42eF695B5dd9911D05Ac944d4cAca3c4EAB);

    constructor (bytes32 _openingRules, bytes32 _closingRules, address _verifier, uint256 _expiration) {
        openingPacketRules = _openingRules;
        closingPacketRules = _closingRules;
        verifier = UltraVerifier(_verifier);
        maxExpiration = _expiration;
    }

    function releaseFunding(bytes32 _index) public returns (bool, uint256) {
        Deal storage deal = deals[_index];

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
        return (success, value);
    }

    function settleAndReleaseFunding(bytes32 _index) public {
        Deal storage deal = deals[_index];
    
        require(deal.openingId > 0, "Deal does not exist.");
        require(deal.expiration >= block.timestamp, 'This deal has expired.');
        require(deal.settledOpen == false || deal.settledClose == false, "Deal has already been settled");

        // Settle packet
        if (!deal.settledOpen) {
            if (settleAndGetAssertionResult(deal.openingId, deal.openingId)) {
                uint256 value = deal.authorizedFunding;
                deal.authorizedFunding = 0;
                (bool success, ) = deal.escrowAddress.call{value: value}("");
                require(success, "The transfer could not be completed."); 
            }
        } else if (!deal.settledClose) {
            if (settleAndGetAssertionResult(deal.openingId, deal.closingId)) {
                uint256 value = deal.authorizedFunding;
                deal.authorizedFunding = 0;
                (bool success, ) = deal.escrowAddress.call{value: value}("");
                require(success, "The transfer could not be completed."); 
            }
        }
    }

    function assertOpeningPacket(bytes memory _packetCID, bytes calldata proof, PacketInputs calldata inputs) public {
        require(inputs.expiration >= block.timestamp + maxExpiration, "Expiration must not exceed 60 days.");

        // Verify input hash matches the packet CID using zk-proof
        bytes32 inputHash = keccak256(abi.encode(inputs));
        require(verifier.verify(proof, split(abi.encodePacked(_packetCID, inputHash))), "Proof is invalid.");

        // Needs a challenge window of 24hrs+
        bytes memory assertion = abi.encodePacked(_packetCID, assertionStatement, closingPacketRules);
        bytes32 assertionId = oov3.assertTruthWithDefaults(assertion, address(this));
        deals[assertionId] = Deal({
            originator          : msg.sender,
            openingId           : assertionId,
            closingId           : bytes32(0x00),
            openingCID          : _packetCID,
            closingCID          : new bytes(36),
            escrowDetails       : inputs.escrowDetails,
            openingDocuments    : inputs.supportingDocuments,
            closingDocuments    : new bytes[](0),
            escrowAddress       : inputs.escrowAddress,
            agentId             : inputs.agentId,
            expiration          : inputs.expiration,
            authorizedFunding   : uint256(0),
            requestedFunding    : inputs.requestedFunding,
            settledOpen         : false,
            settledClose        : false
        });
    }

    function assertClosingPacket(bytes calldata _packetCID, bytes32 _index, bytes calldata proof, PacketInputs memory inputs) public returns (Deal memory) {
        require(inputs.expiration >= block.timestamp + maxExpiration, "Expiration must not exceed 60 days.");
        Deal storage deal = deals[_index];
        
        require(deal.openingId > 0, "Deal does not exist.");
        require(deal.originator == msg.sender, "Caller is unauthorized.");
        require(deal.settledOpen, "Opening packet has not been settled yet");
        require(deal.authorizedFunding == 0, "Remaining funding must be claimed");

        // Verify input hash matches the packet CID using zk-proof
        bytes32 inputHash = keccak256(abi.encode(inputs));
        require(verifier.verify(proof, split(abi.encodePacked(_packetCID, inputHash))), "Proof is invalid.");

        bytes memory assertion = abi.encodePacked(_packetCID, assertionStatement, closingPacketRules);

        deal.closingId = oov3.assertTruthWithDefaults(assertion, address(this));
        deal.closingCID = _packetCID;
        deal.closingDocuments = inputs.supportingDocuments;
        deal.requestedFunding = inputs.requestedFunding;
        deal.expiration = inputs.expiration;

        return deal;
    }

    function cancelDeal(bytes32 _index) public returns (bool) {
        Deal storage deal = deals[_index];

        require(deal.originator == msg.sender, "Caller is unauthorized.");

        deal.requestedFunding = 0;
        deal.authorizedFunding = 0;
        deal.expiration = block.timestamp;

        return (true);
    }

    function settleAndGetAssertionResult(bytes32 _index, bytes32 _assertionId) internal returns (bool) {
        Deal storage deal = deals[_index];

        if (oov3.settleAndGetAssertionResult(_assertionId)) { 
            // Update deal and authorize funding
            if (!deal.settledOpen) {
                deal.settledOpen = true;
                uint256 value = deal.requestedFunding;
                deal.requestedFunding = 0;
                deal.authorizedFunding += value;
            } else if (!deal.settledClose) {
                deal.settledClose = true;
                uint256 value = deal.requestedFunding;
                deal.requestedFunding = 0;
                deal.authorizedFunding += value;
            }
            return true;
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