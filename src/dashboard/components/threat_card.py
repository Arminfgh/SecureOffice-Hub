"""
Threat Card Component
Reusable threat display card for dashboard
"""

import streamlit as st
from typing import Dict, Optional
from datetime import datetime


def threat_card(
    threat_data: Dict,
    show_actions: bool = True,
    compact: bool = False
):
    """
    Display a threat information card
    
    Args:
        threat_data: Threat information dictionary
        show_actions: Show action buttons
        compact: Use compact layout
    """
    threat_id = threat_data.get('threat_id', 'N/A')
    threat_type = threat_data.get('threat_type', 'unknown')
    value = threat_data.get('value', 'N/A')
    threat_level = threat_data.get('threat_level', 'MEDIUM')
    confidence = threat_data.get('confidence', 0.0)
    first_seen = threat_data.get('first_seen', datetime.now().isoformat())
    
    # Color mapping
    color_map = {
        'CRITICAL': '#FF0000',
        'HIGH': '#FF6B00',
        'MEDIUM': '#FFA500',
        'LOW': '#FFD700',
        'SAFE': '#00FF00'
    }
    
    border_color = color_map.get(threat_level, '#808080')
    
    # Card container
    if compact:
        _render_compact_card(threat_data, border_color)
    else:
        _render_full_card(threat_data, border_color, show_actions)


def _render_compact_card(threat_data: Dict, border_color: str):
    """Render compact threat card"""
    st.markdown(f"""
    <div style="
        border-left: 4px solid {border_color};
        padding: 10px;
        margin: 5px 0;
        background: #f0f0f0;
        border-radius: 5px;
    ">
        <strong>{threat_data.get('threat_type', 'unknown').upper()}</strong>: 
        <code>{threat_data.get('value', 'N/A')}</code>
        <span style="float: right; color: {border_color}; font-weight: bold;">
            [{threat_data.get('threat_level', 'MEDIUM')}]
        </span>
    </div>
    """, unsafe_allow_html=True)


def _render_full_card(threat_data: Dict, border_color: str, show_actions: bool):
    """Render full threat card"""
    threat_level = threat_data.get('threat_level', 'MEDIUM')
    confidence = threat_data.get('confidence', 0.0)
    
    # Emoji for threat level
    emoji_map = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'SAFE': '✅'
    }
    emoji = emoji_map.get(threat_level, '⚪')
    
    # Container
    with st.container():
        st.markdown(f"""
        <div style="
            border: 2px solid {border_color};
            border-radius: 10px;
            padding: 15px;
            margin: 10px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <h4 style="margin-top: 0; color: {border_color};">
                {emoji} {threat_level} Threat
            </h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Details
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Type:**")
            st.markdown(f"`{threat_data.get('threat_type', 'N/A')}`")
        
        with col2:
            st.markdown("**Confidence:**")
            st.markdown(f"`{confidence*100:.0f}%`")
        
        with col3:
            st.markdown("**First Seen:**")
            st.markdown(f"`{threat_data.get('first_seen', 'N/A')[:10]}`")
        
        # Value
        st.markdown("**Indicator:**")
        st.code(threat_data.get('value', 'N/A'))
        
        # Metadata
        if threat_data.get('metadata'):
            with st.expander("📋 Additional Information"):
                st.json(threat_data['metadata'])
        
        # Actions
        if show_actions:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button("🔍 Analyze", key=f"analyze_{threat_data.get('threat_id')}"):
                    st.info("Analysis feature")
            
            with col2:
                if st.button("🕸️ Graph", key=f"graph_{threat_data.get('threat_id')}"):
                    st.info("Graph view feature")
            
            with col3:
                if st.button("📊 Details", key=f"details_{threat_data.get('threat_id')}"):
                    st.info("Details view feature")
            
            with col4:
                if st.button("🚨 Alert", key=f"alert_{threat_data.get('threat_id')}"):
                    st.success("Alert created!")


def threat_list(threats: list, max_display: int = 10):
    """
    Display a list of threats
    
    Args:
        threats: List of threat dictionaries
        max_display: Maximum threats to display
    """
    if not threats:
        st.info("No threats to display")
        return
    
    st.markdown(f"### Showing {min(len(threats), max_display)} of {len(threats)} threats")
    
    for threat in threats[:max_display]:
        threat_card(threat, show_actions=False, compact=True)
    
    if len(threats) > max_display:
        st.info(f"+ {len(threats) - max_display} more threats")


def threat_summary_card(stats: Dict):
    """
    Display threat summary statistics
    
    Args:
        stats: Statistics dictionary
    """
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin: 10px 0;
    ">
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Threats",
            stats.get('total', 0),
            delta=stats.get('change', 0)
        )
    
    with col2:
        st.metric(
            "Critical",
            stats.get('critical', 0),
            delta=stats.get('critical_change', 0),
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            "High",
            stats.get('high', 0),
            delta=stats.get('high_change', 0),
            delta_color="inverse"
        )
    
    with col4:
        st.metric(
            "Blocked",
            stats.get('blocked', 0),
            delta=stats.get('blocked_change', 0)
        )
    
    st.markdown("</div>", unsafe_allow_html=True)