// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../src/interfaces/IERC20.sol";
import { LeaseEscrowV1 } from "../src/LeaseEscrowV1.sol";
import { NodeRegistryV1 } from "../src/NodeRegistryV1.sol";

interface VmLike {
    function envAddress(string calldata name) external view returns (address);
    function envUint(string calldata name) external view returns (uint256);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

/// Move node bonds onto a staked asset.
///
/// `NodeRegistryV1.bondToken` is immutable and `LeaseEscrowV1.nodeRegistry` is
/// immutable, so the bond asset cannot be changed in place: a new registry
/// forces a new escrow. This deploys the pair and leaves the old contracts
/// standing so their bonds can still be withdrawn.
///
/// Compute keeps settling in USDG. Only what a node stakes to join changes.
///
/// Run order:
///   1. Drain the old escrow. Every lease must be finalized or refunded, since
///      in-flight leases on the old escrow are invisible to the new one.
///   2. Run this script.
///   3. Re-register every node against the new registry, which pulls the stake
///      from the operator. RegisterCloudBroker.s.sol does this per node once
///      PRISM_NODE_REGISTRY_ADDRESS points at the new registry.
///   4. Repoint PRISM_NODE_REGISTRY_ADDRESS and PRISM_LEASE_ESCROW_ADDRESS in
///      the host env, then restart the services.
///   5. Retire and withdraw on the old registry to recover the old bonds.
contract MigrateToStakedBonds {
    VmLike private constant VM = VmLike(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;

    function run() external returns (NodeRegistryV1 registry, LeaseEscrowV1 escrow) {
        address bondToken = VM.envAddress("PRISM_BOND_TOKEN");
        address admin = VM.envAddress("PRISM_ADMIN_SAFE");
        address gateway = VM.envAddress("PRISM_GATEWAY_SIGNER");
        address attestor = VM.envAddress("PRISM_ATTESTOR_ADDRESS");
        address treasury = VM.envAddress("PRISM_TREASURY_SAFE");

        require(bondToken.code.length != 0, "bond token has no code");
        require(bondToken != USDG, "bond token is still the payment token");

        uint256 perRateUnit = VM.envUint("PRISM_BOND_PER_RATE_UNIT");
        uint256 floor = VM.envUint("PRISM_BOND_FLOOR");
        uint256 ceiling = VM.envUint("PRISM_BOND_CEILING");

        VM.startBroadcast(VM.envUint("PRISM_DEPLOYER_KEY"));
        registry = new NodeRegistryV1(IERC20(bondToken), treasury, perRateUnit, floor, ceiling);
        escrow = new LeaseEscrowV1(
            IERC20(USDG), registry, admin, gateway, attestor, treasury, admin, admin
        );
        // One shot, and the escrow cannot be replaced afterwards.
        registry.setEscrow(address(escrow));
        // The deployer owns the registry only long enough to wire the escrow.
        // The live registry is held by the Safe and the replacement must not be
        // weaker, so hand it over before the broadcast ends.
        registry.transferOwnership(admin);
        VM.stopBroadcast();

        require(address(registry.bondToken()) == bondToken, "bond token did not take");
        require(address(escrow.usd()) == USDG, "compute must still settle in USDG");
        require(address(escrow.nodeRegistry()) == address(registry), "escrow points elsewhere");
        require(registry.owner() == admin, "registry must end up with the Safe");
    }
}
