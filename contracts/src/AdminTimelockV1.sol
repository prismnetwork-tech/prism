// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

contract AdminTimelockV1 {
    uint64 public constant MIN_DELAY = 48 hours;

    struct Operation {
        uint64 executeAfter;
        bool executed;
    }

    error AlreadyScheduled();
    error CallFailed();
    error InvalidAddress();
    error NotAdmin();
    error NotReady();
    error AlreadyExecuted();
    error UnknownOperation();

    event OperationScheduled(
        bytes32 indexed operationId,
        address indexed target,
        uint256 value,
        bytes data,
        uint64 executeAfter
    );
    event OperationExecuted(bytes32 indexed operationId, address indexed target);
    event OperationCancelled(bytes32 indexed operationId);

    address public immutable admin;
    mapping(bytes32 operationId => Operation operation) public operations;

    constructor(address admin_) {
        if (admin_ == address(0)) revert InvalidAddress();
        admin = admin_;
    }

    function schedule(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        onlyAdmin
        returns (bytes32 operationId)
    {
        if (target == address(0)) revert InvalidAddress();
        operationId = hashOperation(target, value, data, salt);
        if (operations[operationId].executeAfter != 0) revert AlreadyScheduled();
        uint64 executeAfter = uint64(block.timestamp + MIN_DELAY);
        operations[operationId] = Operation({ executeAfter: executeAfter, executed: false });
        emit OperationScheduled(operationId, target, value, data, executeAfter);
    }

    function cancel(bytes32 operationId) external onlyAdmin {
        Operation memory operation = operations[operationId];
        if (operation.executeAfter == 0) revert UnknownOperation();
        if (operation.executed) revert AlreadyExecuted();
        delete operations[operationId];
        emit OperationCancelled(operationId);
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        returns (bytes memory result)
    {
        if (target == address(0)) revert InvalidAddress();
        bytes32 operationId = hashOperation(target, value, data, salt);
        Operation storage operation = operations[operationId];
        if (operation.executeAfter == 0) revert UnknownOperation();
        if (operation.executed) revert AlreadyExecuted();
        if (block.timestamp < operation.executeAfter) revert NotReady();
        operation.executed = true;
        (bool success, bytes memory returnData) = target.call{ value: value }(data);
        if (!success) revert CallFailed();
        emit OperationExecuted(operationId, target);
        return returnData;
    }

    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 salt)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, salt));
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }
}
