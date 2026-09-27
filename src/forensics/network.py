"""
src/forensics/network.py
Syndicate Graph Engine for InternKavach
Builds and visualises entity relationship graphs to detect scam syndicates.
"""
from __future__ import annotations

import io
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import matplotlib
matplotlib.use("Agg")   # non-interactive backend for Streamlit
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


# ── Global runtime entity registry (persists across Streamlit reruns via cache) ─
# In production this would be a DB; here we use a module-level dict.
_ENTITY_REGISTRY: Dict[str, List[str]] = {}  # entity_value → [doc_ids that mention it]

# ── Known flagged entities (seed list – mocked threat intelligence) ────────────
try:
    from src.forensics.syndicate import check_certificate_mill, CERTIFICATE_MILLS
except ImportError:
    check_certificate_mill = None
    CERTIFICATE_MILLS = {}

KNOWN_BAD_ACTORS = {
    # UPI handles
    "fraudjobs@ybl", "hiringhub@ibl", "internpay@ptyes",
    "techvision@paytm", "jobsoffer2024@ybl", "indiajobs@axl",
    # Domains
    "internhire.in", "joboffer24.com", "freejobs.co.in",
    "prodigyinfotech.net", "prodigyinfotech.in", "oasisinfobyte.com", "letsgrowmore.in",
    # Phone numbers (last 10 digits)
    "9876543210", "8888888888",
    # Company names & Mass Certificate Mills
    "TechVision Pvt Ltd", "GlobalHR Solutions", "DigiCorp India",
    "Prodigy InfoTech", "Prodigy Infotech", "Oasis Infobyte", "LetsGrowMore",
    "YBI Foundation", "CodSoft", "Bharat Intern", "Internpe",
}

# ── Node colour palette by type ───────────────────────────────────────────────
NODE_COLORS = {
    "Company":   "#FF6B6B",   # red
    "Phone":     "#FFD93D",   # yellow
    "UPI":       "#6BCB77",   # green
    "Domain":    "#4D96FF",   # blue
    "Signatory": "#C77DFF",   # purple
    "IFSC":      "#FF9A3C",   # orange
    "Email":     "#00C9A7",   # teal
}


def _get_node_color(node_type: str) -> str:
    return NODE_COLORS.get(node_type, "#AAAAAA")


def register_entities(doc_id: str, entities: Dict[str, List[str]]) -> None:
    """
    Register entities from a document into the global registry.

    Args:
        doc_id:    Unique document identifier.
        entities:  Dict mapping entity_type → list of entity_values.
                   e.g. {"Company": ["TechVision"], "UPI": ["pay@ybl"]}
    """
    for entity_type, values in entities.items():
        for value in values:
            key = f"{entity_type}::{value.strip().lower()}"
            if key not in _ENTITY_REGISTRY:
                _ENTITY_REGISTRY[key] = []
            if doc_id not in _ENTITY_REGISTRY[key]:
                _ENTITY_REGISTRY[key].append(doc_id)


def build_syndicate_graph(
    entities: Dict[str, List[str]],
    doc_label: str = "Current Document",
) -> Tuple[nx.DiGraph, List[str], bool]:
    """
    Build a directed graph connecting all entities in the document.
    Cross-check against the registry and known bad actors.

    Args:
        entities:  {entity_type: [values]}.
        doc_label: Human-readable label for the document node.

    Returns:
        (G, syndicate_flags, is_syndicate)
    """
    G = nx.DiGraph()
    syndicate_flags: List[str] = []
    is_syndicate = False

    # Add document root node
    G.add_node(doc_label, node_type="Document", color="#FFFFFF")

    all_nodes_by_type: Dict[str, List[str]] = {}

    for entity_type, values in entities.items():
        all_nodes_by_type[entity_type] = []
        for value in values:
            if not value.strip():
                continue

            node_id = f"{value}"
            color   = _get_node_color(entity_type)
            G.add_node(node_id, node_type=entity_type, color=color)
            G.add_edge(doc_label, node_id, relation="contains")
            all_nodes_by_type[entity_type].append(node_id)

            # ── Check known bad actor list / certificate mills ─────────────
            val_lower = value.strip().lower()
            matched_bad = val_lower in {b.lower() for b in KNOWN_BAD_ACTORS}
            mill_info = None
            if check_certificate_mill and entity_type == "Company":
                mill_info = check_certificate_mill(value)

            if matched_bad:
                is_syndicate = True
                syndicate_flags.append(
                    f"[THREAT INTELLIGENCE MATCH] [{entity_type}] '{value}' "
                    f"matches threat intelligence database."
                )
                G.nodes[node_id]["flagged"] = True
            elif mill_info:
                is_syndicate = True
                syndicate_flags.append(
                    f"[CERTIFICATE MILL MATCH] '{mill_info['canonical_name']}' is a known mass unpaid virtual internship mill "
                    f"(~{mill_info.get('complaint_count', '1000+')} student complaints reported)."
                )
                G.nodes[node_id]["flagged"] = True

            # ── Check cross-document matches in registry ────────────────────
            reg_key = f"{entity_type}::{val_lower}"
            if reg_key in _ENTITY_REGISTRY:
                other_docs = [d for d in _ENTITY_REGISTRY[reg_key]
                              if d != doc_label]
                if other_docs:
                    is_syndicate = True
                    syndicate_flags.append(
                        f"[CROSS-DOCUMENT SYNDICATE LINK] [{entity_type}] '{value}' "
                        f"also appears in {len(other_docs)} other document(s): "
                        f"{', '.join(other_docs[:3])}."
                    )
                    for other_doc in other_docs[:2]:
                        if other_doc not in G:
                            G.add_node(other_doc, node_type="Document", color="#888888")
                        G.add_edge(node_id, other_doc, relation="shared_entity")

    # ── Connect same-type entity nodes to each other (intra-cluster) ──────────
    for entity_type, nodes in all_nodes_by_type.items():
        for i, n1 in enumerate(nodes):
            for n2 in nodes[i + 1:]:
                G.add_edge(n1, n2, relation="same_type")

    if is_syndicate and not syndicate_flags:
        syndicate_flags.append("[SHARED ENTITY PATTERN] Recurring entity signature detected across uploads.")

    return G, syndicate_flags, is_syndicate


def render_graph(G: nx.DiGraph, title: str = "Entity Relationship Graph") -> bytes:
    """
    Render the NetworkX graph to a PNG image (bytes) suitable for Streamlit.

    Returns:
        PNG image bytes.
    """
    fig, ax = plt.subplots(figsize=(12, 8), facecolor="#0E1117")
    ax.set_facecolor("#0E1117")
    ax.set_title(title, color="white", fontsize=14, pad=15, fontweight="bold")

    if len(G.nodes) == 0:
        ax.text(0.5, 0.5, "No entities detected.", color="white",
                ha="center", va="center", transform=ax.transAxes, fontsize=14)
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=100, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close(fig)
        return buf.getvalue()

    # Layout
    try:
        pos = nx.spring_layout(G, seed=42, k=2.0 / max(1, len(G.nodes) ** 0.5))
    except Exception:
        pos = nx.circular_layout(G)

    node_colors = [G.nodes[n].get("color", "#AAAAAA") for n in G.nodes]
    flagged     = [n for n in G.nodes if G.nodes[n].get("flagged", False)]
    edge_colors = []
    for u, v, data in G.edges(data=True):
        rel = data.get("relation", "")
        if rel == "shared_entity":
            edge_colors.append("#FF4444")
        elif rel == "same_type":
            edge_colors.append("#444466")
        else:
            edge_colors.append("#556677")

    nx.draw_networkx_nodes(
        G, pos, node_color=node_colors, node_size=800,
        alpha=0.92, ax=ax,
    )
    # Highlight flagged nodes with red ring
    if flagged:
        nx.draw_networkx_nodes(
            G, pos, nodelist=flagged, node_color="red",
            node_size=900, alpha=0.5, ax=ax,
        )

    nx.draw_networkx_edges(
        G, pos, edge_color=edge_colors, arrows=True,
        arrowsize=15, width=1.5, ax=ax,
        connectionstyle="arc3,rad=0.05",
    )

    # Labels – shorten long strings
    labels = {n: (n[:20] + "…" if len(n) > 20 else n) for n in G.nodes}
    nx.draw_networkx_labels(
        G, pos, labels=labels, font_size=7,
        font_color="white", ax=ax,
    )

    # Legend
    legend_handles = [
        mpatches.Patch(color=c, label=t)
        for t, c in NODE_COLORS.items()
    ]
    legend_handles.append(mpatches.Patch(color="#FFFFFF", label="Document"))
    ax.legend(
        handles=legend_handles, loc="upper left",
        framealpha=0.3, facecolor="#1E1E2E", labelcolor="white",
        fontsize=7,
    )

    ax.axis("off")
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    return buf.getvalue()


def clear_registry() -> None:
    """Clear the global entity registry (for testing)."""
    global _ENTITY_REGISTRY
    _ENTITY_REGISTRY.clear()


def generate_syndicate_graph(
    entities: Dict[str, List[str]],
    doc_label: str = "Current Document",
) -> Tuple[Optional[bytes], List[str], bool]:
    """
    Encapsulates registering entities, constructing the syndicate graph,
    and rendering it to PNG bytes.

    Returns:
        (graph_png_bytes, syndicate_flags, is_syndicate)
    """
    clean_entities = {k: v for k, v in entities.items() if v}
    register_entities(doc_label, clean_entities)
    G, flags, is_synd = build_syndicate_graph(clean_entities, doc_label=doc_label)
    try:
        png_bytes = render_graph(G, title=f"Entity Cluster — {doc_label}")
    except Exception:
        png_bytes = None
    return png_bytes, flags, is_synd

