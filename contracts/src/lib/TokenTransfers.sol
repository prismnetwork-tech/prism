// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import { IERC20 } from "../interfaces/IERC20.sol";

library TokenTransfers {
    error TokenTransferFailed();

    function pull(IERC20 token, address from, uint256 amount) internal {
        _call(token, abi.encodeCall(IERC20.transferFrom, (from, address(this), amount)));
    }

    function push(IERC20 token, address to, uint256 amount) internal {
        _call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    }

    function _call(IERC20 token, bytes memory data) private {
        (bool success, bytes memory result) = address(token).call(data);
        if (!success || (result.length != 0 && !abi.decode(result, (bool)))) {
            revert TokenTransferFailed();
        }
    }
}
