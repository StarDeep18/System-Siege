"""
components/charts.py — Plotly chart wrappers for the SOC dashboard.
Each function returns a Plotly figure ready for st.plotly_chart().
"""

from __future__ import annotations

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime


# ── Theme Constants ───────────────────────────────────────────────────────────

CHART_BG = "rgba(0, 0, 0, 0)"
CHART_PAPER_BG = "rgba(0, 0, 0, 0)"
NEON_CYAN = "#00D4FF"
NEON_GREEN = "#00E5A0"
NEON_YELLOW = "#FFD700"
NEON_ORANGE = "#FF8C00"
NEON_RED = "#FF4C4C"
GRID_COLOR = "rgba(0, 212, 255, 0.08)"
TEXT_COLOR = "#94A3B8"


# ── Public Interface ──────────────────────────────────────────────────────────

def threat_timeline(dates: list[datetime], scores: list[int]) -> go.Figure:
    """
    Line chart showing average security risk score trend over time.
    """
    df = pd.DataFrame({"Date": dates, "Score": scores})
    
    fig = go.Figure()
    
    # Grid/Line plot
    fig.add_trace(go.Scatter(
        x=df["Date"], 
        y=df["Score"],
        mode='lines+markers',
        name='Security Index',
        line=dict(color=NEON_CYAN, width=2.5),
        marker=dict(size=6, color="#070B14", line=dict(color=NEON_CYAN, width=1.5)),
        fill='tozeroy',
        fillcolor='rgba(0, 212, 255, 0.05)'
    ))
    
    fig.update_layout(
        margin=dict(l=20, r=20, t=10, b=20),
        height=260,
        xaxis=dict(showgrid=True, gridcolor=GRID_COLOR, tickfont=dict(color=TEXT_COLOR)),
        yaxis=dict(showgrid=True, gridcolor=GRID_COLOR, tickfont=dict(color=TEXT_COLOR), range=[0, 105]),
        showlegend=False
    )
    
    return _apply_dark_theme(fig)


def risk_distribution(dist_dict: dict) -> go.Figure:
    """
    Pie/donut chart of protected assets by risk level.
    """
    labels = list(dist_dict.keys())
    values = list(dist_dict.values())
    
    colors = {
        "Critical": NEON_RED,
        "High": NEON_ORANGE,
        "Medium": NEON_YELLOW,
        "Low": NEON_GREEN
    }
    
    fig = go.Figure(data=[go.Pie(
        labels=labels, 
        values=values, 
        hole=.5,
        marker=dict(colors=[colors.get(l, NEON_CYAN) for l in labels], line=dict(color='#0D1421', width=2)),
        textinfo='percent',
        hoverinfo='label+value'
    )])
    
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        height=260,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(color=TEXT_COLOR, size=10)
        )
    )
    
    return _apply_dark_theme(fig)


def vulnerability_bar(vuln_dict: dict) -> go.Figure:
    """
    Horizontal bar chart showing vulnerability categories.
    """
    df = pd.DataFrame({
        "Category": list(vuln_dict.keys()),
        "Count": list(vuln_dict.values())
    }).sort_values("Count", ascending=True)
    
    fig = go.Figure(go.Bar(
        x=df["Count"],
        y=df["Category"],
        orientation='h',
        marker=dict(
            color=NEON_CYAN,
            line=dict(color='rgba(0, 212, 255, 0.4)', width=1)
        ),
        text=df["Count"],
        textposition='inside',
        textfont=dict(color='#070B14', weight='bold')
    ))
    
    fig.update_layout(
        margin=dict(l=20, r=20, t=10, b=20),
        height=260,
        xaxis=dict(showgrid=True, gridcolor=GRID_COLOR, tickfont=dict(color=TEXT_COLOR)),
        yaxis=dict(tickfont=dict(color=TEXT_COLOR))
    )
    
    return _apply_dark_theme(fig)


def _apply_dark_theme(fig: go.Figure) -> go.Figure:
    """Apply the SentinelAI dark theme styling details."""
    fig.update_layout(
        paper_bgcolor=CHART_PAPER_BG,
        plot_bgcolor=CHART_BG,
        font=dict(family="'Outfit', sans-serif", color=TEXT_COLOR)
    )
    return fig
