pragma solidity ^0.5.11;

contract ownershipContract {
    
    //The keyword "public" makes those variables readable from outside and inside.
    //The address type is a 160-bit value that doesn't allow any arithmetic operations
    address public consortium;
    
    //This declares a new complex type which will be used for variables later. It will represent a single device.
    struct info {
        address owner;
        address[] ownershipHistory;
        uint challenge;
        uint response;
        uint pubKey;
    }
    
    //The type maps addresses to unsigned integers. Mappings can be seen as hash tables which are virtually initialized such that
    //every possible key exists and is mapped to a value whose byte-representation is all zeros.
    mapping (uint => info) public idInfo;
    
    // This is the constructor whose code is run only when the contract is created.
    constructor () public {
        consortium = msg.sender;
    }
    
    uint deviceIdentifier;

    function registerDevice(uint _identifier, uint _challenge, uint _response, uint _pubKey) public {
        idInfo[_identifier].owner = msg.sender;
        idInfo[_identifier].ownershipHistory.push(msg.sender);
        idInfo[_identifier].challenge = _challenge;
        idInfo[_identifier].response = _response;
        idInfo[_identifier].pubKey = _pubKey;
    }
    
    function checkOwnership(uint _identifier) public view returns (address _ownerName, address [] memory _ownershipHistory) {
        _ownerName = idInfo[_identifier].owner;
        _ownershipHistory = idInfo[_identifier].ownershipHistory;
    }
    
    function authenticateDevice(uint _identifier) public view returns (uint _challenge, uint _response, uint _pubKey) {
        _challenge = idInfo[_identifier].challenge;
        _response = idInfo[_identifier].response;
        _pubKey = idInfo[_identifier].pubKey;
    }
    
    function transferOwnership(uint _identifier, address buyer) public {
        //If the first argument of `require` evaluates to `false`, execution terminates and all changes to the state 
		//and to Ether balances are reverted.
		//Use assert(x) if you never ever want x to be false, not in any circumstance (apart from a bug in your code). 
		//Use require(x) if x can be false, due to e.g. invalid input or a failing external component.
		require(
            msg.sender == idInfo[_identifier].owner,
            "Only device owner can transfer the ownership."
        );
        idInfo[_identifier].owner = buyer;
        idInfo[_identifier].ownershipHistory.push(buyer);
    }
    
    function results(uint _identifier) public view returns(address, uint, uint, uint)
    {
        return(idInfo[_identifier].owner, idInfo[_identifier].challenge, idInfo[_identifier].response, idInfo[_identifier].pubKey);
    }
}
