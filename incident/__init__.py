"""incident — Operational SOC layer. Aggregates pipeline outputs into Incidents, Reports, and Alerts."""
from incident.builder import (
    build_incident,
    build_alerts,
    build_executive_report,
    build_technical_report,
    build_dashboard_summary,
    report_to_json_bytes,
    report_to_pdf_bytes,
)
from incident.models import Incident, ExecutiveReport, TechnicalReport, DashboardSummary

__all__ = [
    "build_incident",
    "build_alerts",
    "build_executive_report",
    "build_technical_report",
    "build_dashboard_summary",
    "report_to_json_bytes",
    "report_to_pdf_bytes",
    "Incident",
    "ExecutiveReport",
    "TechnicalReport",
    "DashboardSummary",
]
