from importlib.metadata import version
from unittest.mock import patch

import prism_agentkit
import prismnetwork
from prism_agentkit import PrismActionProvider
from prismnetwork import DEFAULT_IMAGE, Lease


class FakeAgent:
    address = "0x0000000000000000000000000000000000000001"

    def __init__(self):
        self.ended = []
        self.last_lease = None

    def balances(self):
        return {
            "address": self.address,
            "usdg": 1_250_000,
            "eth": 2_000_000_000_000_000_000,
        }

    def offers(self):
        return [
            {
                "gpu": {"model": "Test GPU", "vram_mib": 24_576},
                "rate_per_second": 25,
                "trust_class": "isolated",
            }
        ]

    def lease(self, **kwargs):
        self.last_lease = kwargs
        return Lease(
            lease_id=7,
            access={},
            key_path="",
            key_dir="",
            public_key="",
            funding_hash="0x01",
            quote={},
        )

    def run(self, lease, command):
        return {"code": 0, "stdout": f"{lease.lease_id}:{command}", "stderr": ""}

    def end_lease(self, lease):
        self.ended.append(lease.lease_id)


assert version("prismnetwork") == prismnetwork.__version__
assert version("prism-agentkit") == prism_agentkit.__version__
assert DEFAULT_IMAGE.startswith("docker.io/") and "@sha256:" in DEFAULT_IMAGE

agent = FakeAgent()
provider = PrismActionProvider(agent)
prefix = "PrismActionProvider_"
actions = {action.name.removeprefix(prefix): action for action in provider.get_actions(None)}
assert set(actions) == {"wallet", "list_gpus", "lease_and_run", "run", "end_lease"}

with patch("coinbase_agentkit.action_providers.action_decorator.send_analytics_event"):
    assert "1.250000 USDG" in actions["wallet"].invoke({})
    listed = actions["list_gpus"].invoke({})
    assert "Test GPU" in listed and "isolated" in listed
    leased = actions["lease_and_run"].invoke(
        {
            "command": "nvidia-smi",
            "duration_seconds": 120,
            "min_vram_mib": 8192,
            "max_usdg": 0.25,
            "min_trust_class": "isolated",
        }
    )
    assert "lease 7 funded onchain" in leased
    assert agent.last_lease == {
        "image": DEFAULT_IMAGE,
        "duration_seconds": 120,
        "min_vram_mib": 8192,
        "max_deposit": 250_000,
        "min_trust_class": "isolated",
    }
    assert actions["run"].invoke({"lease_id": 7, "command": "echo ready"}).endswith("7:echo ready")
    assert actions["end_lease"].invoke({"lease_id": 7}) == "released lease 7"
assert agent.ended == [7]

print("Python SDK and AgentKit wheels are importable and actions are callable")
