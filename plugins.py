"""Host-installed capability bindings. MCP requests never load Python modules."""

from collections.abc import Callable
from dataclasses import dataclass
import unicodedata

from pydantic import Field

from policy_engine import Contract, digest, wire


@dataclass(frozen=True)
class Binding:
    name: str
    plugin: str
    description: str
    arguments: type[Contract]
    invoke: Callable[[Contract], dict]

    def tool(self):
        return {"name": self.name, "description": self.description,
                "inputSchema": self.arguments.model_json_schema()}

    @property
    def sha256(self):
        return digest(wire(self.tool()))


class ReportPreview(Contract):
    text: str = Field(min_length=1, max_length=4096)


def preview(arguments: ReportPreview) -> dict:
    text = unicodedata.normalize("NFC", arguments.text)
    return {"characters": len(text), "words": len(text.split()), "sha256": digest(text.encode("utf-8"))}


REPORTS = Binding("reports.preview", "reports-v1", "Summarize the supplied report text without storing it.",
                  ReportPreview, preview)


def host_catalog():
    return (REPORTS,)
