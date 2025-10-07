"""
Graph Visualizer Component
Interactive network graph visualization
"""

import streamlit as st
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


def create_interactive_graph(
    nodes: List[Dict],
    edges: List[Dict],
    height: str = "600px",
    physics: bool = True
) -> Network:
    """
    Create interactive network graph
    
    Args:
        nodes: List of node dictionaries
        edges: List of edge dictionaries
        height: Graph height
        physics: Enable physics simulation
        
    Returns:
        PyVis Network object
    """
    net = Network(
        height=height,
        width="100%",
        bgcolor="#222222",
        font_color="white",
        directed=True
    )
    
    # Color mapping
    color_map = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6B00",
        "MEDIUM": "#FFA500",
        "LOW": "#FFD700",
        "SAFE": "#00FF00"
    }
    
    # Shape mapping
    shape_map = {
        "ip_address": "diamond",
        "domain": "dot",
        "url": "square",
        "file_hash": "triangle",
        "email": "star",
        "campaign": "hexagon",
        "malware": "triangleDown"
    }
    
    # Add nodes
    for node in nodes:
        node_id = node.get('id')
        label = node.get('label', node_id)
        node_type = node.get('type', 'unknown')
        threat_level = node.get('threat_level', 'MEDIUM')
        
        net.add_node(
            node_id,
            label=label,
            color=color_map.get(threat_level, "#AAAAAA"),
            shape=shape_map.get(node_type, "dot"),
            size=25,
            title=f"Type: {node_type}<br>Level: {threat_level}<br>Value: {label}"
        )
    
    # Add edges
    for edge in edges:
        source = edge.get('source')
        target = edge.get('target')
        label = edge.get('label', '')
        
        net.add_edge(
            source,
            target,
            label=label,
            color="#FFFFFF",
            arrows="to"
        )
    
    # Set physics options
    if physics:
        net.set_options("""
        {
            "physics": {
                "enabled": true,
                "barnesHut": {
                    "gravitationalConstant": -30000,
                    "centralGravity": 0.3,
                    "springLength": 200,
                    "springConstant": 0.04
                },
                "minVelocity": 0.75
            },
            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.5
                    }
                },
                "color": {
                    "inherit": false
                },
                "font": {
                    "size": 12,
                    "color": "#ffffff"
                }
            },
            "interaction": {
                "hover": true,
                "tooltipDelay": 100,
                "zoomView": true,
                "dragView": true
            }
        }
        """)
    
    return net


def display_graph(net: Network):
    """
    Display network graph in Streamlit
    
    Args:
        net: PyVis Network object
    """
    # Save to temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        net.save_graph(tmp.name)
        html_file = Path(tmp.name)
        
        # Read and display
        html_content = html_file.read_text()
        components.html(html_content, height=650)


def graph_with_controls(
    nodes: List[Dict],
    edges: List[Dict],
    title: str = "Threat Network"
):
    """
    Display graph with interactive controls
    
    Args:
        nodes: List of nodes
        edges: List of edges
        title: Graph title
    """
    st.markdown(f"### {title}")
    
    # Controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        physics = st.checkbox("Enable Physics", value=True)
    
    with col2:
        node_filter = st.multiselect(
            "Filter Node Types",
            ["ip_address", "domain", "url", "file_hash", "campaign"],
            default=["ip_address", "domain", "url"]
        )
    
    with col3:
        severity_filter = st.multiselect(
            "Filter Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH"]
        )
    
    # Apply filters
    filtered_nodes = [
        n for n in nodes
        if n.get('type') in node_filter and n.get('threat_level') in severity_filter
    ]
    
    # Filter edges to only include filtered nodes
    node_ids = {n['id'] for n in filtered_nodes}
    filtered_edges = [
        e for e in edges
        if e['source'] in node_ids and e['target'] in node_ids
    ]
    
    # Create and display graph
    if filtered_nodes:
        net = create_interactive_graph(filtered_nodes, filtered_edges, physics=physics)
        display_graph(net)
        
        # Stats
        st.markdown("#### Graph Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Nodes", len(filtered_nodes))
        
        with col2:
            st.metric("Edges", len(filtered_edges))
        
        with col3:
            avg_connections = len(filtered_edges) / len(filtered_nodes) if filtered_nodes else 0
            st.metric("Avg Connections", f"{avg_connections:.1f}")
    else:
        st.warning("No nodes match the current filters")


def simple_graph_preview(
    nodes: List[Dict],
    edges: List[Dict],
    height: str = "300px"
):
    """
    Simple graph preview without controls
    
    Args:
        nodes: List of nodes
        edges: List of edges
        height: Graph height
    """
    if not nodes:
        st.info("No graph data available")
        return
    
    net = create_interactive_graph(nodes, edges, height=height, physics=False)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        net.save_graph(tmp.name)
        html_file = Path(tmp.name)
        html_content = html_file.read_text()
        components.html(html_content, height=350)


def graph_legend():
    """Display graph legend"""
    with st.expander("📖 Graph Legend"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Severity Colors:**")
            st.markdown("🔴 Critical")
            st.markdown("🟠 High")
            st.markdown("🟡 Medium")
            st.markdown("🟢 Low/Safe")
        
        with col2:
            st.markdown("**Node Shapes:**")
            st.markdown("◆ IP Address")
            st.markdown("● Domain")
            st.markdown("■ URL")
            st.markdown("▲ File Hash")
            st.markdown("★ Email")
            st.markdown("⬡ Campaign")


def export_graph(net: Network, filename: str = "threat_graph.html"):
    """
    Export graph to HTML file
    
    Args:
        net: PyVis Network object
        filename: Output filename
    """
    net.save_graph(filename)
    
    with open(filename, 'r') as f:
        html_content = f.read()
    
    st.download_button(
        label="📥 Download Graph",
        data=html_content,
        file_name=filename,
        mime="text/html"
    )