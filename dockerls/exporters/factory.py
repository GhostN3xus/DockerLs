from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.exporters.csv_exporter import CSVExporter
from dockerls.exporters.html_exporter import HTMLExporter
from dockerls.exporters.json_exporter import JSONExporter
from dockerls.exporters.markdown_exporter import MarkdownExporter
from dockerls.exporters.sarif_exporter import SARIFExporter

if TYPE_CHECKING:
    from dockerls.exporters.base import ExporterInterface


class ExporterFactory:
    _exporters: dict[str, type[ExporterInterface]] = {
        "json": JSONExporter,
        "csv": CSVExporter,
        "html": HTMLExporter,
        "markdown": MarkdownExporter,
        "md": MarkdownExporter,
        "sarif": SARIFExporter,
    }

    @classmethod
    def create(cls, format_name: str) -> ExporterInterface:
        key = format_name.lower()
        if key not in cls._exporters:
            supported = ", ".join(sorted(cls._exporters.keys()))
            raise ValueError(f"Unsupported format: {format_name}. Supported: {supported}")
        return cls._exporters[key]()
