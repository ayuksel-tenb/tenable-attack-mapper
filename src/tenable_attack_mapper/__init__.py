"""Map Tenable Security Center findings to MITRE ATT&CK techniques.

The package is intentionally free of any Claude Code / runtime coupling so it can
run standalone (CLI), under an MCP server, or be imported as a library.
"""

from .models import Finding, TechniqueMapping, TechniqueScore
from .pipeline import MapResult, run

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "TechniqueMapping",
    "TechniqueScore",
    "MapResult",
    "run",
    "__version__",
]
