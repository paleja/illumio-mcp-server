import pytest
import os
import dotenv
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from illumio import PolicyComputeEngine, Label

dotenv.load_dotenv()


def get_server_params():
    """MCP server startup parameters."""
    venv_python = os.path.join(
        os.path.dirname(__file__), "..", ".venv", "bin", "python3"
    )
    env = {
        **os.environ,
        "PCE_HOST": os.getenv("PCE_HOST", ""),
        "PCE_PORT": os.getenv("PCE_PORT", ""),
        "PCE_ORG_ID": os.getenv("PCE_ORG_ID", ""),
        "API_KEY": os.getenv("API_KEY", ""),
        "API_SECRET": os.getenv("API_SECRET", ""),
    }
    return StdioServerParameters(
        command=venv_python,
        args=["-m", "illumio_mcp"],
        env=env,
    )


def get_pce() -> PolicyComputeEngine:
    pce = PolicyComputeEngine(
        os.getenv("PCE_HOST"),
        port=os.getenv("PCE_PORT"),
        org_id=os.getenv("PCE_ORG_ID"),
    )
    pce.set_credentials(os.getenv("API_KEY"), os.getenv("API_SECRET"))
    pce._session.verify = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")
    return pce


@pytest.fixture(scope="session", autouse=True)
def ensure_pos_label():
    """Ensure the app=pos label exists on the PCE before any tests run."""
    pce = get_pce()
    existing = pce.labels.get(params={"key": "app", "value": "pos"})

    if not existing:
        pce.labels.create(Label(key="app", value="pos"))

    yield
