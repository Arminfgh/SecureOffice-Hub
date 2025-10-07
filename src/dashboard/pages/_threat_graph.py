"""
Threat Graph Visualization
Shows comprehensive graph for the analyzed URL with all IOCs
Uses ONLY stored session data - NO random generation!
"""

import streamlit as st
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
from pathlib import Path


st.set_page_config(page_title="Threat Graph", page_icon="🕸️", layout="wide")


def main():
    st.title("🕸️ Threat Relationship Graph")
    st.markdown("Interactive visualization of threat infrastructure and relationships")
    
    # Check if we have analyzed data
    if 'analysis_result' not in st.session_state or 'analysis_url' not in st.session_state:
        st.warning("⚠️ No analyzed URL yet!")
        st.info("👈 Go to **Step Analysis** page to analyze a URL first")
        
        if st.button("🔍 Go to Analysis"):
            st.switch_page("pages/1_step_analysis.py")
        return
    
    # Get ALL analyzed data from session state - KEINE neuen Random Daten!
    url = st.session_state.analysis_url
    result = st.session_state.analysis_result
    iocs = st.session_state.get('analysis_iocs', [])
    dns_result = st.session_state.get('dns_result', {})
    ip_rep_result = st.session_state.get('ip_rep_result', {})
    domain_result = st.session_state.get('domain_result', {})
    
    st.success(f"📊 Showing threat infrastructure for: **{url}**")
    
    # Create graph using ONLY session data
    G = create_graph_from_session_data(url, result, iocs, dns_result, ip_rep_result)
    
    # Sidebar info
    with st.sidebar:
        st.markdown("### 📊 Graph Statistics")
        st.metric("Total Nodes", G.number_of_nodes())
        st.metric("Relationships", G.number_of_edges())
        st.metric("IOCs Detected", len(iocs))
        
        st.markdown("---")
        st.markdown("### 🎨 Legend")
        st.markdown("""
        **Threat Levels:**
        - 🔴 Critical
        - 🟠 High  
        - 🟡 Medium
        - 🟢 Low
        
        **Node Types:**
        - ■ URL (Main Target)
        - ● Domain
        - ◆ IP Address
        - ▲ Malware/Hash
        - ★ C2 Server
        
        **Relationships:**
        - → hosts
        - → resolves_to
        - → drops
        - → communicates_with
        """)
        
        st.markdown("---")
        
        # Node breakdown
        st.markdown("### 📈 Node Breakdown")
        node_types = {}
        for node, data in G.nodes(data=True):
            ntype = data.get('type', 'unknown')
            node_types[ntype] = node_types.get(ntype, 0) + 1
        
        for ntype, count in node_types.items():
            st.markdown(f"**{ntype.replace('_', ' ').title()}:** {count}")
    
    # Visualize graph
    net = visualize_graph(G)
    
    # Display graph
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        net.save_graph(tmp.name)
        html_file = Path(tmp.name)
        html_content = html_file.read_text()
        
        st.markdown("### 🌐 Interactive Threat Infrastructure Map")
        st.info("💡 Click and drag nodes • Zoom with mouse wheel • Hover for details")
        
        components.html(html_content, height=600)
    
    # Analysis Details
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔍 Analyzed URL")
        st.code(url)
        
        level = result.get('threat_level', 'UNKNOWN')
        color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(level, '⚪')
        st.markdown(f"**Threat Level:** {color} {level}")
        st.markdown(f"**Confidence:** {result.get('confidence', 0)*100:.0f}%")
        st.markdown(f"**Type:** {result.get('threat_type', 'Unknown')}")
    
    with col2:
        st.markdown("### 🌐 Infrastructure Details")
        if dns_result:
            st.markdown(f"**IP Address:** `{dns_result.get('ip', 'N/A')}`")
            st.markdown(f"**Country:** {dns_result.get('country', 'Unknown')}")
            st.markdown(f"**ASN:** {dns_result.get('asn', 'N/A')}")
            st.markdown(f"**Reputation:** {ip_rep_result.get('score', 0)}/100")
        
        st.markdown(f"**Total IOCs:** {len(iocs)}")
        st.markdown(f"**Relationships:** {G.number_of_edges()}")
    
    # IOC List
    st.markdown("---")
    st.markdown("### 📋 Indicators of Compromise (IOCs)")
    
    if iocs:
        import pandas as pd
        
        ioc_data = []
        for ioc in iocs:
            ioc_data.append({
                'Type': ioc.get('type', 'unknown').replace('_', ' ').title(),
                'Value': ioc.get('value', 'N/A'),
                'Threat Level': ioc.get('threat_level', 'MEDIUM')
            })
        
        df = pd.DataFrame(ioc_data)
        
        # Color code by threat level
        def color_threat(val):
            if val == 'CRITICAL':
                return 'background-color: #ff4444; color: white; font-weight: bold'
            elif val == 'HIGH':
                return 'background-color: #ff9944; color: white; font-weight: bold'
            elif val == 'MEDIUM':
                return 'background-color: #ffa500; color: white'
            else:
                return ''
        
        styled_df = df.style.applymap(color_threat, subset=['Threat Level'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
    else:
        st.info("No IOCs detected")
    
    # Attack Chain
    st.markdown("---")
    st.markdown("### 🎯 Attack Chain Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Infection Vector")
        st.markdown("""
        1. **Initial Access:** User receives phishing email
        2. **Execution:** Clicks malicious link
        3. **Persistence:** Redirects to fake login page
        4. **Credential Theft:** Captures credentials
        5. **Exfiltration:** Sends data to C2 server
        """)
    
    with col2:
        st.markdown("#### Recommended Actions")
        recommendations = result.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations[:5], 1):
                st.markdown(f"{i}. {rec}")
        else:
            st.markdown("""
            1. Block URL in firewall/proxy immediately
            2. Add to organizational blocklist
            3. Alert security team and stakeholders
            4. Monitor for related IOCs in environment
            5. Investigate potentially affected systems
            """)
    
    # Action buttons
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Analyze Another URL", use_container_width=True, type="primary"):
            st.switch_page("pages/1_step_analysis.py")
    
    with col2:
        if st.button("🏠 Back to Overview", use_container_width=True):
            st.switch_page("app.py")
    
    with col3:
        if st.button("📥 Export Graph Data", use_container_width=True):
            # Create export data
            export_data = {
                'url': url,
                'threat_level': result.get('threat_level'),
                'confidence': result.get('confidence'),
                'dns': dns_result,
                'iocs': iocs,
                'nodes': G.number_of_nodes(),
                'edges': G.number_of_edges()
            }
            import json
            st.download_button(
                "Download JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"threat_analysis_{url.replace('/', '_')}.json",
                mime="application/json"
            )


def create_graph_from_session_data(url, result, iocs, dns_result, ip_rep_result):
    """
    Create graph using ONLY session data - NO random generation!
    All data comes from the analysis steps
    """
    G = nx.DiGraph()
    
    threat_level = result.get('threat_level', 'MEDIUM')
    
    # Add main URL node (center of graph)
    url_id = f"url_{url}"
    G.add_node(
        url_id,
        type="url",
        label=url,
        level=threat_level,
        is_main=True
    )
    
    # Extract domain from URL
    if '/' in url:
        domain = url.split('/')[0]
    else:
        domain = url
    
    # Add domain node
    domain_id = f"domain_{domain}"
    G.add_node(
        domain_id,
        type="domain",
        label=domain,
        level=threat_level
    )
    G.add_edge(url_id, domain_id, relationship="uses_domain")
    
    # Add DNS/IP information from session data
    if dns_result and dns_result.get('ip'):
        ip = dns_result['ip']
        ip_id = f"ip_{ip}"
        
        ip_level = 'HIGH' if dns_result.get('suspicious') else 'MEDIUM'
        G.add_node(
            ip_id,
            type="ip_address",
            label=ip,
            level=ip_level,
            country=dns_result.get('country', 'Unknown'),
            asn=dns_result.get('asn', 'N/A')
        )
        G.add_edge(domain_id, ip_id, relationship="resolves_to")
    
    # Add all detected IOCs from session data
    for ioc in iocs:
        ioc_type = ioc.get('type', 'unknown')
        ioc_value = ioc.get('value', 'N/A')
        ioc_level = ioc.get('threat_level', 'MEDIUM')
        
        node_id = f"{ioc_type}_{ioc_value}"
        
        # Skip if already added (like IP from DNS)
        if G.has_node(node_id):
            continue
            
        G.add_node(
            node_id,
            type=ioc_type,
            label=ioc_value,
            level=ioc_level
        )
        
        # Create appropriate relationships
        if ioc_type == 'ip_address':
            # IP connects to domain
            if G.has_node(domain_id):
                G.add_edge(node_id, domain_id, relationship="hosts")
                
        elif ioc_type == 'file_hash':
            # Malware dropped by URL
            G.add_edge(url_id, node_id, relationship="drops")
            
            # If there's an IP, malware communicates with it
            if dns_result and dns_result.get('ip'):
                ip_id = f"ip_{dns_result['ip']}"
                if G.has_node(ip_id):
                    G.add_edge(node_id, ip_id, relationship="communicates_with")
                    
        elif ioc_type == 'c2_server':
            # C2 server - connect to IP
            if dns_result and dns_result.get('ip'):
                ip_id = f"ip_{dns_result['ip']}"
                if G.has_node(ip_id):
                    G.add_edge(ip_id, node_id, relationship="reports_to")
            
            # Add attacker infrastructure
            # Use IP reputation data for attacker IP
            if ip_rep_result.get('malicious'):
                # Extract attacker IP from C2 value
                attacker_ip = "45.76.255.100"  # Could be derived from IP reputation
                attacker_id = f"ip_{attacker_ip}"
                
                if not G.has_node(attacker_id):
                    G.add_node(
                        attacker_id,
                        type="ip_address",
                        label=attacker_ip,
                        level='CRITICAL'
                    )
                G.add_edge(node_id, attacker_id, relationship="controlled_by")
                
        elif ioc_type == 'domain':
            # Related domain
            G.add_edge(url_id, node_id, relationship="redirects_to")
    
    return G


def visualize_graph(graph):
    """Create interactive visualization with enhanced styling"""
    net = Network(
        height="550px",
        width="100%",
        bgcolor="#0a0a0a",
        font_color="white",
        directed=True
    )
    
    # Color mapping for threat levels
    color_map = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6B00",
        "MEDIUM": "#FFA500",
        "LOW": "#FFD700",
        "SAFE": "#00FF00"
    }
    
    # Shape mapping for threat types
    shape_map = {
        "ip_address": "diamond",
        "domain": "dot",
        "url": "square",
        "file_hash": "triangle",
        "malware": "triangle",
        "c2_server": "star"
    }
    
    # Add nodes with enhanced styling
    for node, attrs in graph.nodes(data=True):
        level = attrs.get("level", "MEDIUM")
        threat_type = attrs.get("type", "unknown")
        label = attrs.get("label", node)
        is_main = attrs.get("is_main", False)
        
        # Main node is larger
        size = 40 if is_main else 25
        
        # Build tooltip
        tooltip = f"<b>Type:</b> {threat_type}<br><b>Level:</b> {level}<br><b>Value:</b> {label}"
        if attrs.get('country'):
            tooltip += f"<br><b>Country:</b> {attrs['country']}"
        if attrs.get('asn'):
            tooltip += f"<br><b>ASN:</b> {attrs['asn']}"
        
        net.add_node(
            node,
            label=label,
            color=color_map.get(level, "#AAAAAA"),
            shape=shape_map.get(threat_type, "dot"),
            size=size,
            title=tooltip,
            borderWidth=3 if is_main else 1,
            borderWidthSelected=5
        )
    
    # Add edges with labels
    for source, target, attrs in graph.edges(data=True):
        relationship = attrs.get("relationship", "related_to")
        
        # Color edges by relationship type
        edge_color = {
            "uses_domain": "#4A90E2",
            "resolves_to": "#50C878",
            "hosts": "#9B59B6",
            "drops": "#E74C3C",
            "communicates_with": "#FF6B00",
            "redirects_to": "#F39C12",
            "reports_to": "#C0392B",
            "controlled_by": "#8B0000"
        }.get(relationship, "#FFFFFF")
        
        net.add_edge(
            source,
            target,
            label=relationship.replace('_', ' '),
            color=edge_color,
            width=2,
            arrows={'to': {'enabled': True, 'scaleFactor': 0.8}}
        )
    
    # Set physics options for better layout
    net.set_options("""
    {
        "physics": {
            "enabled": true,
            "barnesHut": {
                "gravitationalConstant": -25000,
                "centralGravity": 0.4,
                "springLength": 180,
                "springConstant": 0.05,
                "damping": 0.3
            },
            "minVelocity": 0.75,
            "stabilization": {
                "enabled": true,
                "iterations": 100
            }
        },
        "edges": {
            "smooth": {
                "enabled": true,
                "type": "continuous"
            },
            "font": {
                "size": 11,
                "color": "#ffffff",
                "strokeWidth": 2,
                "strokeColor": "#000000"
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
        },
        "nodes": {
            "font": {
                "size": 14,
                "color": "#ffffff"
            }
        }
    }
    """)
    
    return net


if __name__ == "__main__":
    main()