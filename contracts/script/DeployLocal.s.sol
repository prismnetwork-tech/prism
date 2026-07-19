// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { LeaseEscrowV1 } from "../src/LeaseEscrowV1.sol";
import { NodeRegistryV1 } from "../src/NodeRegistryV1.sol";

interface VmLocal {
    function addr(uint256 privateKey) external returns (address);
    function envBytes32(string calldata name) external returns (bytes32);
    function envUint(string calldata name) external returns (uint256);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract LocalUsd is IERC20 {
    mapping(address account => uint256) public balanceOf;
    mapping(address owner => mapping(address spender => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 approved = allowance[from][msg.sender];
        if (approved != type(uint256).max) allowance[from][msg.sender] = approved - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract LocalManifest {
    LocalUsd public immutable usd;
    NodeRegistryV1 public immutable registry;
    LeaseEscrowV1 public immutable escrow;
    bytes32 public immutable nodeId;
    uint256 public immutable leaseId;

    constructor(
        LocalUsd usd_,
        NodeRegistryV1 registry_,
        LeaseEscrowV1 escrow_,
        bytes32 nodeId_,
        uint256 leaseId_
    ) {
        usd = usd_;
        registry = registry_;
        escrow = escrow_;
        nodeId = nodeId_;
        leaseId = leaseId_;
    }
}

contract DeployLocal {
    VmLocal private constant VM =
        VmLocal(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (LocalManifest manifest) {
        uint256 deployerKey = VM.envUint("PRISM_LOCAL_DEPLOYER_KEY");
        uint256 gatewayKey = VM.envUint("PRISM_LOCAL_GATEWAY_KEY");
        uint256 attestorKey = VM.envUint("PRISM_LOCAL_ATTESTOR_KEY");
        uint256 providerKey = VM.envUint("PRISM_LOCAL_PROVIDER_KEY");
        bytes32 nodeId = VM.envBytes32("PRISM_LOCAL_NODE_ID");
        (LocalUsd usd, NodeRegistryV1 registry, LeaseEscrowV1 escrow) =
            _deploy(deployerKey, gatewayKey, attestorKey, providerKey);
        _register(usd, registry, nodeId, providerKey);
        uint256 leaseId = _createLease(usd, escrow, nodeId, deployerKey);

        VM.startBroadcast(deployerKey);
        manifest = new LocalManifest(usd, registry, escrow, nodeId, leaseId);
        VM.stopBroadcast();
    }

    function _deploy(
        uint256 deployerKey,
        uint256 gatewayKey,
        uint256 attestorKey,
        uint256 providerKey
    ) private returns (LocalUsd usd, NodeRegistryV1 registry, LeaseEscrowV1 escrow) {
        address deployer = VM.addr(deployerKey);
        VM.startBroadcast(deployerKey);
        usd = new LocalUsd();
        registry = new NodeRegistryV1(usd, deployer);
        escrow = new LeaseEscrowV1(
            usd,
            registry,
            deployer,
            VM.addr(gatewayKey),
            VM.addr(attestorKey),
            deployer,
            deployer,
            deployer
        );
        registry.setEscrow(address(escrow));
        escrow.unpause();
        usd.mint(VM.addr(providerKey), 200_000_000);
        usd.mint(deployer, 50_000_000);
        VM.stopBroadcast();
    }

    function _register(
        LocalUsd usd,
        NodeRegistryV1 registry,
        bytes32 nodeId,
        uint256 providerKey
    ) private {
        address provider = VM.addr(providerKey);
        bytes32 metadataHash = keccak256("local-node");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = registry.enrollmentDigest(
            nodeId, nodeId, provider, provider, 100, metadataHash, 0, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(providerKey, digest);
        VM.startBroadcast(providerKey);
        usd.approve(address(registry), type(uint256).max);
        registry.register(
            nodeId,
            nodeId,
            provider,
            100,
            metadataHash,
            deadline,
            abi.encodePacked(r, s, v)
        );
        VM.stopBroadcast();
    }

    function _createLease(
        LocalUsd usd,
        LeaseEscrowV1 escrow,
        bytes32 nodeId,
        uint256 deployerKey
    ) private returns (uint256 leaseId) {
        VM.startBroadcast(deployerKey);
        usd.approve(address(escrow), type(uint256).max);
        leaseId = escrow.createLease(nodeId, 60, keccak256("local-quote"));
        VM.stopBroadcast();
    }
}
