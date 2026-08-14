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

import prism_autogen
import prism_crewai
import prism_langchain
from prismnetwork import PrismToolset


class FakeToolsetAgent(FakeAgent):
    def offers(self, min_trust="open"):
        return super().offers()


assert version("prism-langchain") == prism_langchain.__version__
assert version("prism-crewai") == prism_crewai.__version__
assert version("prism-autogen") == prism_autogen.__version__

toolset = PrismToolset(agent=FakeToolsetAgent())
listed = toolset.list_gpus()
assert "Test GPU" in listed and "isolated" in listed
assert "lease 7 funded onchain" in toolset.lease_and_run("nvidia-smi", max_usdg=0.25)
assert toolset.run(7, "echo ready").endswith("7:echo ready")
assert toolset.end_lease(7) == "released lease 7"

expected = ["prism_wallet", "prism_list_gpus", "prism_lease_and_run", "prism_run", "prism_end_lease"]

lc_tools = prism_langchain.get_prism_tools(PrismToolset(agent=FakeToolsetAgent()))
assert [t.name for t in lc_tools] == expected
assert "Test GPU" in lc_tools[1].invoke({"min_trust": "open"})

crew_tools = prism_crewai.prism_tools(PrismToolset(agent=FakeToolsetAgent()))
assert len(crew_tools) == 5 and all(t.args_schema is not None for t in crew_tools)
assert "Test GPU" in crew_tools[1].run(min_trust="open")

ag_tools = prism_autogen.prism_tools(PrismToolset(agent=FakeToolsetAgent()))
assert [f.__name__ for f in ag_tools] == expected
assert all(f.__doc__ for f in ag_tools)
assert "Test GPU" in ag_tools[1]("open")

print("Python SDK, AgentKit and integration wheels are importable and their tools are callable")
