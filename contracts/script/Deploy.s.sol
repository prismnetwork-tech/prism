// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {IERC20, IERC20Metadata} from "../src/interfaces/IERC20.sol";
import {AdminTimelockV1} from "../src/AdminTimelockV1.sol";
import {LeaseEscrowV1} from "../src/LeaseEscrowV1.sol";
import {NodeRegistryV1} from "../src/NodeRegistryV1.sol";

interface Vm {
    function envAddress(string calldata name) external returns (address value);
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract Deploy {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;

    function run()
        external
        returns (NodeRegistryV1 registry, LeaseEscrowV1 escrow, AdminTimelockV1 timelock)
    {
        address admin = VM.envAddress("PRISM_ADMIN_SAFE");
        address gateway = VM.envAddress("PRISM_GATEWAY_SIGNER");
        address attestor = VM.envAddress("PRISM_ATTESTOR_ADDRESS");
        address treasury = VM.envAddress("PRISM_TREASURY_SAFE");
        require(USDG.code.length != 0, "USDG code missing");
        require(IERC20Metadata(USDG).decimals() == 6, "unexpected USDG decimals");

        VM.startBroadcast();
        timelock = new AdminTimelockV1(admin);
        registry = new NodeRegistryV1(IERC20(USDG), treasury);
        escrow = new LeaseEscrowV1(
            IERC20(USDG), registry, address(timelock), gateway, attestor, treasury, admin, admin
        );
        registry.setEscrow(address(escrow));
        registry.transferOwnership(address(timelock));
        VM.stopBroadcast();
    }
}
