// The contract for Dave to buy a writer position

pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Strings.sol";
contract Contract_D {
    uint256 public T_W;
    address public buyer;
    address public seller;
    uint256 constant delta = 10 minutes;
    bytes32 public old_exercise_hashlock;
    bytes32 public exercise_hashlock;
    address public old_writer_transfer_public_key;
    address public writer_transfer_public_key;
    bool public is_revealed;
    uint256 public transfer_time;
    bytes32 public fixed_r;

    constructor(
        uint256 _T_W,
        address _seller,
        bytes32 _exercise_hashlock,
        bytes32 _old_exercise_hashlock,
        address _writer_transfer_public_key,
        address _old_writer_transfer_public_key,
        bytes32 _fixed_r
    ) payable {
        buyer = msg.sender;
        T_W = _T_W;
        seller = _seller;
        old_exercise_hashlock = _old_exercise_hashlock;
        exercise_hashlock = _exercise_hashlock;
        writer_transfer_public_key = _writer_transfer_public_key;
        old_writer_transfer_public_key = _old_writer_transfer_public_key;
        fixed_r = _fixed_r;
    }

    function reveal(bytes32 s, uint8 v) public {
        string memory message = string.concat(Strings.toHexString(uint256(uint160(address(buyer))), 20), Strings.toHexString(uint256(exercise_hashlock), 32), Strings.toHexString(uint256(uint160(writer_transfer_public_key)), 20));
        require(verify(message, fixed_r, s, v) == old_writer_transfer_public_key, "Invalid signature");
        
        require(msg.sender == seller, "Not the seller");  
        require(block.timestamp <= T_W - delta, "Timelock expired");  
        transfer_time = block.timestamp;
        is_revealed = true;
    }

    function withdraw() public {
        require(is_revealed == true, "Preimage hasn't been reveal");
        require(transfer_time + 3 * delta < block.timestamp, "Delayed withdrawal period");
        seller.call{value: address(this).balance}("");
    }

    function refund() public {
        require(msg.sender == buyer, "Only buyer can refund");
        require(block.timestamp > T_W + delta, "Timelock hasn't expired");  
        buyer.call{value: address(this).balance}("");
    }

    // can't verify the secret key directly, thus verify one specific signature with "r", "s", "v"
    function reclaim(bytes32 _preimage, bytes32 s, uint8 v) public {
        require(msg.sender == buyer, "Only buyer can reclaim");
        require(transfer_time >= block.timestamp - delta);
        require((sha256(abi.encodePacked(_preimage)) == old_exercise_hashlock) || 
                (verify("Specific Message", fixed_r, s, v) == old_writer_transfer_public_key), "Secret key or preimage not match"); 
        
        buyer.call{value: address(this).balance}("");
    }

    function verify(string memory message, bytes32 r, bytes32 s, uint8 v) internal pure returns (address) {
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        return ecrecover(messageHash, v, r, s);
    }
}