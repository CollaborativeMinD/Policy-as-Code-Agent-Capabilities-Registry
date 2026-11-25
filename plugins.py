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
    return (REPORTS, *KB)

class Search(Contract):
    query: str = Field(min_length=1, max_length=256, pattern=r"\S")
    limit: int = Field(default=3, ge=1, le=3)


class Catalog(Contract):
    pass


class Draft(Contract):
    customer_message: str = Field(min_length=1, max_length=2048)


ARTICLES = (
    ("python-env", "Creating a Python virtual environment", "Create a virtual environment with `python -m venv .venv`, then activate it before installing dependencies."),
    ("reset-password", "Resetting your password", "Open Account Settings, choose Security, and select Reset Password. A verification email will be sent."),
    ("api-rate-limit", "Understanding API rate limits", "API rate limits restrict the number of requests allowed within a time window. Clients should retry using exponential backoff after receiving a rate-limit response."),
)


def search(args):
    hits = [{"id": key, "title": title, "body": body} for key, title, body in ARTICLES
            if args.query.casefold() in (title + " " + body).casefold()]
    return {"articles": hits[:args.limit]}


def catalog(args):
    return {"articles": [{"id": key, "title": title} for key, title, _ in ARTICLES]}


def draft(args):
    return {"messages": [{"role": "user", "content": {"type": "text", "text":
            "Draft a concise reply using retrieved KB evidence. Do not invent product policy."}},
            {"role": "user", "content": {"type": "text", "text": args.customer_message}}]}


KB = (Binding("kb.search", "support-kb", "Search the local support knowledge base.", Search, search),
      Binding("kb.catalog", "support-kb", "List support article identifiers and titles.", Catalog, catalog),
      Binding("kb.draft", "support-kb", "Prepare an evidence-bound support reply prompt.", Draft, draft))
