"""Fail before trusted-host provisioning when inherited controls forbid the lane."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from boundary_contract import check_environment

if __name__ == "__main__":
    check_environment(os.environ)
