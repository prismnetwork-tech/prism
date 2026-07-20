// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "../src/interfaces/IERC20.sol";
import {NodeRegistryV1} from "../src/NodeRegistryV1.sol";

interface VmCloudBroker {
    function addr(uint256 privateKey) external returns (address);
    function envAddress(string calldata name) external returns (address);
    function envBytes32(string calldata name) external returns (bytes32);
    function envUint(string calldata name) external returns (uint256);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract RegisterCloudBroker {
    VmCloudBroker private constant VM =
        VmCloudBroker(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint128 private constant RATE_PER_SECOND = 222;
    bytes32 private constant METADATA_HASH = keccak256("prism.vast.l40s.direct-ssh.v1");

    function run() external {
        uint256 operatorKey = VM.envUint("PRISM_CLOUD_OPERATOR_KEY");
        NodeRegistryV1 registry =
            NodeRegistryV1(VM.envAddress("PRISM_NODE_REGISTRY_ADDRESS"));
        bytes32 nodeId = VM.envBytes32("PRISM_VAST_NODE_ID");
        address operator = VM.addr(operatorKey);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = registry.enrollmentDigest(
            nodeId,
            nodeId,
            operator,
            operator,
            RATE_PER_SECOND,
            METADATA_HASH,
            registry.enrollmentNonces(operator),
            deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(operatorKey, digest);

        VM.startBroadcast(operatorKey);
        IERC20 usd = registry.usd();
        usd.approve(address(registry), registry.requiredBond(RATE_PER_SECOND));
        registry.register(
            nodeId,
            nodeId,
            operator,
            RATE_PER_SECOND,
            METADATA_HASH,
            deadline,
            abi.encodePacked(r, s, v)
        );
        VM.stopBroadcast();
    }
}
