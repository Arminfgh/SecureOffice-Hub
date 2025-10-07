"""
Risk Meter Component
Visual risk level indicator for dashboard
"""

import streamlit as st
import plotly.graph_objects as go
from typing import Optional


def risk_meter(
    risk_score: float,
    title: str = "Risk Level",
    show_details: bool = True
):
    """
    Display a risk meter gauge
    
    Args:
        risk_score: Risk score (0.0 to 1.0)
        title: Meter title
        show_details: Show detailed breakdown
    """
    # Ensure score is between 0 and 1
    risk_score = max(0.0, min(1.0, risk_score))
    
    # Determine risk level
    if risk_score >= 0.8:
        level = "CRITICAL"
        color = "#FF0000"
    elif risk_score >= 0.6:
        level = "HIGH"
        color = "#FF6B00"
    elif risk_score >= 0.4:
        level = "MEDIUM"
        color = "#FFA500"
    elif risk_score >= 0.2:
        level = "LOW"
        color = "#FFD700"
    else:
        level = "SAFE"
        color = "#00FF00"
    
    # Create gauge chart
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 24}},
        delta={'reference': 50, 'increasing': {'color': "red"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 20], 'color': '#E8F5E9'},
                {'range': [20, 40], 'color': '#FFF9C4'},
                {'range': [40, 60], 'color': '#FFE0B2'},
                {'range': [60, 80], 'color': '#FFCCBC'},
                {'range': [80, 100], 'color': '#FFCDD2'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=60, b=20),
        font={'color': "darkblue", 'family': "Arial"}
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Risk level badge
    st.markdown(f"""
    <div style="
        text-align: center;
        padding: 10px;
        background: {color};
        color: white;
        border-radius: 5px;
        font-size: 20px;
        font-weight: bold;
        margin: 10px 0;
    ">
        {level} RISK
    </div>
    """, unsafe_allow_html=True)
    
    # Details
    if show_details:
        with st.expander("📊 Risk Breakdown"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Risk Score", f"{risk_score:.2f}")
                st.metric("Percentage", f"{risk_score*100:.1f}%")
            
            with col2:
                st.metric("Risk Level", level)
                st.metric("Status", "⚠️ Requires Action" if risk_score >= 0.6 else "✅ Acceptable")


def risk_trend_chart(risk_history: list, days: int = 7):
    """
    Display risk trend over time
    
    Args:
        risk_history: List of (date, risk_score) tuples
        days: Number of days to display
    """
    import pandas as pd
    
    if not risk_history:
        st.info("No historical data available")
        return
    
    # Create dataframe
    df = pd.DataFrame(risk_history, columns=['Date', 'Risk Score'])
    df['Date'] = pd.to_datetime(df['Date'])
    
    # Sort by date
    df = df.sort_values('Date')
    df = df.tail(days)
    
    # Create line chart
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df['Date'],
        y=df['Risk Score'] * 100,
        mode='lines+markers',
        name='Risk Score',
        line=dict(color='#667eea', width=3),
        marker=dict(size=8),
        fill='tozeroy',
        fillcolor='rgba(102, 126, 234, 0.2)'
    ))
    
    # Add threshold lines
    fig.add_hline(y=80, line_dash="dash", line_color="red", annotation_text="Critical")
    fig.add_hline(y=60, line_dash="dash", line_color="orange", annotation_text="High")
    fig.add_hline(y=40, line_dash="dash", line_color="yellow", annotation_text="Medium")
    
    fig.update_layout(
        title=f"Risk Trend (Last {days} Days)",
        xaxis_title="Date",
        yaxis_title="Risk Score (%)",
        yaxis=dict(range=[0, 100]),
        height=400,
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)


def risk_comparison(current_risk: float, previous_risk: float):
    """
    Display risk comparison
    
    Args:
        current_risk: Current risk score
        previous_risk: Previous risk score
    """
    change = current_risk - previous_risk
    change_percent = (change / previous_risk * 100) if previous_risk > 0 else 0
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Current Risk",
            f"{current_risk*100:.1f}%",
            delta=f"{change_percent:+.1f}%",
            delta_color="inverse"
        )
    
    with col2:
        st.metric(
            "Previous Risk",
            f"{previous_risk*100:.1f}%"
        )
    
    with col3:
        st.metric(
            "Change",
            f"{abs(change)*100:.1f}%",
            delta="↑ Increased" if change > 0 else "↓ Decreased"
        )


def mini_risk_indicator(risk_score: float, label: str = "Risk"):
    """
    Small inline risk indicator
    
    Args:
        risk_score: Risk score (0.0 to 1.0)
        label: Indicator label
    """
    # Determine color
    if risk_score >= 0.8:
        color = "#FF0000"
        icon = "🔴"
    elif risk_score >= 0.6:
        color = "#FF6B00"
        icon = "🟠"
    elif risk_score >= 0.4:
        color = "#FFA500"
        icon = "🟡"
    elif risk_score >= 0.2:
        color = "#FFD700"
        icon = "🟢"
    else:
        color = "#00FF00"
        icon = "✅"
    
    st.markdown(f"""
    <div style="
        display: inline-block;
        padding: 5px 10px;
        background: {color};
        color: white;
        border-radius: 5px;
        font-size: 14px;
        font-weight: bold;
    ">
        {icon} {label}: {risk_score*100:.0f}%
    </div>
    """, unsafe_allow_html=True)