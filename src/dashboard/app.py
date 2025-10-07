"""
Threat Overview Dashboard Page - REAL DATA ONLY
Shows only actual analysis results, no demo data
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import requests


st.set_page_config(page_title="Threat Overview", page_icon="📊", layout="wide")

API_BASE_URL = "http://localhost:8000"


def get_real_stats():
    """Get real statistics from API"""
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None


def main():
    # BVB Header with Armin's name
    st.markdown("""
        <div style="background: linear-gradient(90deg, #FDE100 0%, #000000 100%); 
                    padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div style="font-size: 3rem;">⚫🟡</div>
                <div style="flex-grow: 1; text-align: center;">
                    <h1 style="color: white; margin: 0;">🛡️ ThreatScope</h1>
                    <p style="color: white; margin: 0;">AI-Powered Threat Intelligence Platform</p>
                </div>
                <div style="font-size: 3rem;">🟡⚫</div>
            </div>
            <div style="text-align: center; margin-top: 1rem; color: white; font-size: 1.1rem;">
                ⭐ <strong>Directed by Armin Foroughi</strong> ⭐
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("Real-time threat monitoring and analysis")
    
    # Get real stats
    stats = get_real_stats()
    
    if not stats:
        st.warning("⚠️ Cannot connect to API - Start backend server")
        st.code("uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload")
        return
    
    # Key Metrics Row - REAL DATA
    st.markdown("### 📈 Platform Statistics (Real-Time)")
    
    graph_stats = stats.get('graph', {})
    
    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
    
    with metric_col1:
        total_threats = graph_stats.get('total_nodes', 0)
        st.metric(
            label="📊 Total IOCs",
            value=total_threats,
            delta="Tracked Indicators"
        )
    
    with metric_col2:
        total_edges = graph_stats.get('total_edges', 0)
        st.metric(
            label="🔗 Relationships",
            value=total_edges,
            delta="Connections"
        )
    
    with metric_col3:
        density = graph_stats.get('density', 0)
        st.metric(
            label="📈 Graph Density",
            value=f"{density:.2%}",
            delta="Network"
        )
    
    with metric_col4:
        connected = "✅ Yes" if graph_stats.get('is_connected') else "❌ No"
        st.metric(
            label="🌐 Connected",
            value=connected
        )
    
    st.markdown("---")
    
    # Check if we have analyzed URLs in session
    has_analysis = 'analysis_result' in st.session_state
    
    if has_analysis:
        # Show recent analysis
        st.markdown("### 🔍 Latest Analysis")
        
        result = st.session_state.analysis_result
        url = st.session_state.analysis_url
        dns = st.session_state.get('dns_result', {})
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Analyzed URL:**")
            st.code(url)
        
        with col2:
            level = result.get('threat_level', 'UNKNOWN')
            color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(level, '⚪')
            st.markdown("**Threat Level:**")
            st.markdown(f"# {color} {level}")
        
        with col3:
            confidence = result.get('confidence', 0) * 100
            st.markdown("**Confidence:**")
            st.markdown(f"# {confidence:.0f}%")
        
        with col4:
            st.markdown("**Location:**")
            st.markdown(f"# {dns.get('country', 'Unknown')}")
        
        # IOCs Summary
        if 'analysis_iocs' in st.session_state:
            iocs = st.session_state.analysis_iocs
            st.markdown(f"**IOCs Detected:** {len(iocs)}")
            
            # IOC type breakdown
            ioc_types = {}
            for ioc in iocs:
                ioc_type = ioc.get('type', 'unknown')
                ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            if ioc_types:
                ioc_df = pd.DataFrame([
                    {'Type': k.replace('_', ' ').title(), 'Count': v} 
                    for k, v in ioc_types.items()
                ])
                
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.pie(
                        ioc_df, 
                        values='Count', 
                        names='Type',
                        title='IOC Distribution',
                        hole=0.4
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.bar(
                        ioc_df,
                        x='Type',
                        y='Count',
                        title='IOC Count by Type',
                        color='Count',
                        color_continuous_scale='Reds'
                    )
                    st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
    
    else:
        # No analysis yet
        st.info("💡 **No analyses performed yet.** Start by analyzing a URL!")
        
        st.markdown("### 🚀 Quick Start")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Get Started:**
            1. Click **"Step Analysis"** in sidebar
            2. Enter a URL to analyze
            3. Watch the 7-step real-time analysis
            4. View threat graph and relationships
            """)
        
        with col2:
            st.markdown("""
            **Test URLs:**
            - `google.com` (Should be CLEAN)
            - `paypal.com` (Should be CLEAN)
            - `paypa1-secure.tk` (Should be CRITICAL)
            - `bankofamerica-alert.xyz` (Suspicious)
            """)
    
    # System Info
    st.markdown("---")
    st.markdown("### ℹ️ System Information")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**🔧 Backend Status**")
        if stats:
            st.success("✅ API Connected")
            st.info(f"Total Nodes: {graph_stats.get('total_nodes', 0)}")
        else:
            st.error("❌ API Offline")
    
    with col2:
        st.markdown("**🤖 AI Analysis**")
        import os
        from dotenv import load_dotenv
        load_dotenv()
        
        openai_key = os.getenv("OPENAI_API_KEY", "")
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        
        if openai_key:
            st.success("✅ OpenAI Configured")
        else:
            st.warning("⚠️ OpenAI Not Configured")
        
        if vt_key:
            st.success("✅ VirusTotal Configured")
        else:
            st.warning("⚠️ VirusTotal Not Configured")
    
    with col3:
        st.markdown("**📊 Data Sources**")
        st.info("✅ DNS Resolver")
        st.info("✅ WHOIS Database")
        st.info("✅ IP Geolocation")
        st.info("✅ SSL Verification")
    
    # Quick Actions
    st.markdown("---")
    st.markdown("### ⚡ Quick Actions")
    
    action_col1, action_col2, action_col3, action_col4 = st.columns(4)
    
    with action_col1:
        if st.button("🔍 **Start Analysis**", use_container_width=True, type="primary"):
            st.switch_page("pages/1_step_analysis.py")
    
    with action_col2:
        if st.button("🕸️ **View Graph**", use_container_width=True):
            if has_analysis:
                st.switch_page("pages/2_threat_graph.py")
            else:
                st.warning("Analyze a URL first!")
    
    with action_col3:
        if st.button("📊 **API Docs**", use_container_width=True):
            st.info("Opening API documentation...")
            st.markdown("[Click here for API docs](http://localhost:8000/docs)")
    
    with action_col4:
        if st.button("⚙️ **Settings**", use_container_width=True):
            st.switch_page("pages/3_settings.py")
    
    # Platform Features
    st.markdown("---")
    st.markdown("## 🚀 Platform Capabilities")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔍 Real-Time Analysis
        - **VirusTotal Integration** - Malware database
        - **DNS Resolution** - Real IP lookup
        - **WHOIS Lookup** - Domain information
        - **IP Geolocation** - Geographic tracking
        - **SSL Verification** - Certificate validation
        - **Pattern Recognition** - Phishing detection
        - **AI Analysis** - GPT-4 powered assessment
        """)
    
    with col2:
        st.markdown("""
        ### 🛡️ Security Features
        - **Graph-based Analysis** - Relationship mapping
        - **Multi-stage Detection** - 7 verification steps
        - **Voice Feedback** - Audio explanations
        - **IOC Tracking** - Indicator of Compromise
        - **Real-time Threat Intel** - Live API queries
        - **Export Capabilities** - JSON reports
        - **No Demo Data** - 100% real analysis
        """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
        <div style="text-align: center; color: #888; padding: 2rem;">
            <p><strong>ThreatScope v1.0</strong> - Real-Time Threat Intelligence</p>
            <p>🟡⚫ Interview Project for Borussia Dortmund 🟡⚫</p>
            <p>Created by <strong>Armin Foroughi</strong></p>
            <p style="font-size: 0.9rem; margin-top: 1rem;">
                Powered by: VirusTotal • OpenAI GPT-4 • NetworkX • Python • FastAPI • Streamlit
            </p>
        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()