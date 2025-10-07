"""
Dashboard Formatters
Formatting utilities specific to dashboard display
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Any, Dict, List


def format_metric_card(label: str, value: Any, delta: Any = None, color: str = "#667eea"):
    """
    Format metric as colored card
    
    Args:
        label: Metric label
        value: Metric value
        delta: Change value
        color: Card color
    """
    st.markdown(f"""
    <div style="
        background: {color};
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 10px 0;
    ">
        <div style="font-size: 14px; opacity: 0.9;">{label}</div>
        <div style="font-size: 32px; font-weight: bold; margin: 10px 0;">{value}</div>
        {f'<div style="font-size: 16px;">↑ {delta}</div>' if delta else ''}
    </div>
    """, unsafe_allow_html=True)


def format_alert_badge(severity: str, count: int = None):
    """
    Format alert severity badge
    
    Args:
        severity: Alert severity
        count: Optional count
    """
    colors = {
        'CRITICAL': '#FF0000',
        'HIGH': '#FF6B00',
        'MEDIUM': '#FFA500',
        'LOW': '#FFD700'
    }
    
    color = colors.get(severity, '#808080')
    display_text = f"{severity}" if count is None else f"{severity} ({count})"
    
    st.markdown(f"""
    <span style="
        background: {color};
        color: white;
        padding: 5px 15px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
        margin: 5px;
    ">
        {display_text}
    </span>
    """, unsafe_allow_html=True)


def format_status_indicator(status: str, text: str = None):
    """
    Format status indicator with icon
    
    Args:
        status: Status type (success, warning, error, info)
        text: Status text
    """
    icons = {
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'info': 'ℹ️'
    }
    
    colors = {
        'success': '#00c851',
        'warning': '#ffbb33',
        'error': '#ff4444',
        'info': '#33b5e5'
    }
    
    icon = icons.get(status, 'ℹ️')
    color = colors.get(status, '#808080')
    display_text = text or status.capitalize()
    
    st.markdown(f"""
    <div style="
        background: {color};
        color: white;
        padding: 10px;
        border-radius: 5px;
        display: inline-block;
    ">
        {icon} {display_text}
    </div>
    """, unsafe_allow_html=True)


def format_timeline_item(time: str, event: str, severity: str = "INFO"):
    """
    Format timeline event item
    
    Args:
        time: Event time
        event: Event description
        severity: Event severity
    """
    icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'INFO': 'ℹ️'
    }
    
    icon = icons.get(severity, 'ℹ️')
    
    st.markdown(f"""
    <div style="
        border-left: 3px solid #667eea;
        padding-left: 15px;
        margin: 10px 0;
    ">
        <div style="font-size: 12px; color: #888;">{time}</div>
        <div style="font-size: 16px;">{icon} {event}</div>
    </div>
    """, unsafe_allow_html=True)


def format_progress_bar(value: float, label: str = "", show_percent: bool = True):
    """
    Format progress bar
    
    Args:
        value: Progress value (0.0 to 1.0)
        label: Progress label
        show_percent: Show percentage
    """
    percent = int(value * 100)
    
    # Color based on progress
    if percent < 30:
        color = "#ff4444"
    elif percent < 70:
        color = "#ffbb33"
    else:
        color = "#00c851"
    
    st.markdown(f"""
    <div style="margin: 10px 0;">
        {f'<div style="margin-bottom: 5px;">{label}</div>' if label else ''}
        <div style="
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
        ">
            <div style="
                background: {color};
                width: {percent}%;
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 12px;
                font-weight: bold;
            ">
                {f'{percent}%' if show_percent else ''}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def format_data_table(data: List[Dict], headers: List[str]):
    """
    Format data as HTML table
    
    Args:
        data: List of data dictionaries
        headers: Table headers
    """
    if not data:
        st.info("No data to display")
        return
    
    # Build table HTML
    table_html = """
    <table style="width: 100%; border-collapse: collapse;">
        <thead>
            <tr style="background: #667eea; color: white;">
    """
    
    for header in headers:
        table_html += f"<th style='padding: 10px; text-align: left;'>{header}</th>"
    
    table_html += "</tr></thead><tbody>"
    
    for i, row in enumerate(data):
        bg_color = "#f9f9f9" if i % 2 == 0 else "white"
        table_html += f"<tr style='background: {bg_color};'>"
        
        for header in headers:
            value = row.get(header.lower().replace(' ', '_'), 'N/A')
            table_html += f"<td style='padding: 10px; border-bottom: 1px solid #ddd;'>{value}</td>"
        
        table_html += "</tr>"
    
    table_html += "</tbody></table>"
    
    st.markdown(table_html, unsafe_allow_html=True)


def format_tag_list(tags: List[str], max_display: int = 10):
    """
    Format list of tags
    
    Args:
        tags: List of tag strings
        max_display: Maximum tags to display
    """
    if not tags:
        st.caption("No tags")
        return
    
    tags_html = ""
    for tag in tags[:max_display]:
        tags_html += f"""
        <span style="
            background: #667eea;
            color: white;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 12px;
            margin: 3px;
            display: inline-block;
        ">
            #{tag}
        </span>
        """
    
    if len(tags) > max_display:
        tags_html += f"""
        <span style="
            color: #888;
            font-size: 12px;
            margin-left: 5px;
        ">
            +{len(tags) - max_display} more
        </span>
        """
    
    st.markdown(tags_html, unsafe_allow_html=True)


def format_code_block(code: str, language: str = "python"):
    """
    Format code with syntax highlighting
    
    Args:
        code: Code string
        language: Programming language
    """
    st.code(code, language=language)


def format_json_pretty(data: Dict):
    """
    Format JSON data prettily
    
    Args:
        data: Dictionary to display
    """
    import json
    st.json(json.dumps(data, indent=2, default=str))


def format_download_button(data: str, filename: str, label: str = "Download"):
    """
    Format download button
    
    Args:
        data: Data to download
        filename: Download filename
        label: Button label
    """
    st.download_button(
        label=f"📥 {label}",
        data=data,
        file_name=filename,
        mime="text/plain"
    )


def format_info_box(title: str, content: str, icon: str = "ℹ️"):
    """
    Format information box
    
    Args:
        title: Box title
        content: Box content
        icon: Icon emoji
    """
    st.markdown(f"""
    <div style="
        background: #e3f2fd;
        border-left: 4px solid #2196f3;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    ">
        <div style="font-weight: bold; margin-bottom: 5px;">
            {icon} {title}
        </div>
        <div>{content}</div>
    </div>
    """, unsafe_allow_html=True)


def format_comparison_metric(
    label: str,
    current: Any,
    previous: Any,
    format_fn = str
):
    """
    Format comparison metric showing change
    
    Args:
        label: Metric label
        current: Current value
        previous: Previous value
        format_fn: Function to format values
    """
    if isinstance(current, (int, float)) and isinstance(previous, (int, float)):
        change = current - previous
        change_percent = (change / previous * 100) if previous != 0 else 0
        delta_text = f"{change:+.0f} ({change_percent:+.1f}%)"
    else:
        delta_text = "Changed"
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(label, format_fn(current))
    
    with col2:
        st.caption("Previous")
        st.text(format_fn(previous))
    
    with col3:
        st.caption("Change")
        st.text(delta_text)