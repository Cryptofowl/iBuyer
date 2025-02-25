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