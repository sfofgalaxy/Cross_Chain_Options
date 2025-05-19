// The contract for the option holder of the holder collateral-free option protocol

pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Strings.sol";

contract Contract_A {
    bytes32 public exercise_hashlock;
    bytes32 public activate_hashlock;
    bytes32 public old_exercise_hashlock;
    // The option expireation and activate timeout
    uint256 public T_E;
    uint256 public T_A;
    address public holder;
    address public writer;
    // Worst-case time to inclusion of the transaction
    uint256 constant delta = 10 minutes;
    // Transfer public key;
    address public holder_transfer_public_key;
    address public writer_transfer_public_key;
    address public old_writer_transfer_public_key;
    uint256 public writer_transfer_time;
    uint256 public exercise_time;
    bytes32 public fixed_r;
    bool public is_activated;
    uint256 asset;
    uint256 guarantee;

    struct NewWriter {
        address writer;
        bytes32 hashlock;
        address transfer_public_key;
    }

    struct NewHolder {
        address holder;
        address transfer_public_key;
    }
    NewWriter public new_writer;
    NewHolder public new_holder;

    constructor(
        bytes32 _exercise_hashlock,
        bytes32 _activate_hashlock,
        uint256 _T_E,
        uint256 _T_A,
        address _holder,
        address _writer_transfer_public_key,
        address _holder_transfer_public_key,
        bytes32 _fixed_r,
        uint256 _asset
    ) payable {
        guarantee == msg.value;
        writer = msg.sender;  // Set the sender to the creator (writer) of the contract
        exercise_hashlock = _exercise_hashlock;  // Set the hashlock
        activate_hashlock = _activate_hashlock;
        T_E = _T_E;  // Set the timeout of the option
        T_A = _T_A;
        holder = _holder;  // Set the intended recipient (holder) of the funds
        writer_transfer_public_key = _writer_transfer_public_key;
        holder_transfer_public_key = _holder_transfer_public_key;
        fixed_r = _fixed_r;
        asset = _asset;
    }

    function activate(bytes32 _preimage) public {
        require(sha256(abi.encodePacked(_preimage)) == activate_hashlock, "Invalid preimage");  
        require(block.timestamp <= T_A, "Activation expired");  
        is_activated = true;
    }

    // If not activate
    function refund() public {
        require(block.timestamp > T_A && is_activated == false, "Timelock hasn't expired");  
        writer.call{value: address(this).balance}("");
    }

    function exercise() public payable {
        require(msg.sender == holder, "Only holder can transfer");
        require(block.timestamp <= T_E + delta, "Timelock expired");  
        require(msg.value == asset, "Asset amount");
        require(exercise_time == 0, "Exercised");  
        exercise_time = block.timestamp;
    }

    function claim() public {
        require(exercise_time != 0 && exercise_time <= block.timestamp - delta, "One delta after exercise required");  
        holder.call{value: address(this).balance}("");
    }

    function fulfill(bytes32 _preimage) public {
        require(sha256(abi.encodePacked(_preimage)) == exercise_hashlock, "Invalid preimage");  
        require(block.timestamp <= T_E + delta, "Timelock expired");  
        writer.call{value: address(this).balance}("");
    }

    function transferHolder(NewHolder memory _new_holder, bytes32 s, uint8 v) public {
        require(is_activated);
        string memory message = string.concat(Strings.toHexString(uint256(uint160(address(_new_holder.holder))), 20), Strings.toHexString(uint256(uint160(_new_holder.transfer_public_key)), 20));
        require(verify(message, fixed_r, s, v) == holder_transfer_public_key, "Invalid signature");
        
        holder = _new_holder.holder;
        holder_transfer_public_key = _new_holder.transfer_public_key;
    }

    function transferWriter(NewWriter memory _new_writer, bytes32 s, uint8 v) public {
        require(is_activated);
        string memory message = string.concat(Strings.toHexString(uint256(uint160(address(_new_writer.writer))), 20), Strings.toHexString(uint256(_new_writer.hashlock), 32), Strings.toHexString(uint256(uint160(_new_writer.transfer_public_key)), 20));
        require(verify(message, fixed_r, s, v) == writer_transfer_public_key, "Invalid signature");
        
        old_exercise_hashlock = exercise_hashlock;
        exercise_hashlock = _new_writer.hashlock;
        holder = _new_writer.writer;
        old_writer_transfer_public_key = writer_transfer_public_key;
        writer_transfer_public_key = _new_writer.transfer_public_key;

        writer_transfer_time = block.timestamp;
    }

    // can't verify the secret key directly, thus verify one specific signature with "r", "s", "v"
    function reclaim(bytes32 _preimage, bytes32 s, uint8 v) public {
        require(msg.sender == writer, "Only writer can reclaim");
        require(writer_transfer_time >= block.timestamp - delta);
        require((sha256(abi.encodePacked(_preimage)) == old_exercise_hashlock) || 
                (verify("Specific Message", fixed_r, s, v) == old_writer_transfer_public_key), "Secret key or preimage not match"); 
        
        holder.call{value: address(this).balance}("");
    }

    function verify(string memory message, bytes32 r, bytes32 s, uint8 v) internal pure returns (address) {
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        return ecrecover(messageHash, v, r, s);
    }
}