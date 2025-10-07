"""
Dashboard Chart Utilities
Helper functions for creating charts and visualizations
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List, Dict, Optional


def create_severity_pie_chart(severity_counts: Dict) -> go.Figure:
    """
    Create pie chart for threat severity distribution
    
    Args:
        severity_counts: Dictionary of severity levels and counts
        
    Returns:
        Plotly figure
    """
    colors = {
        'CRITICAL': '#FF0000',
        'HIGH': '#FF6B00',
        'MEDIUM': '#FFA500',
        'LOW': '#FFD700',
        'SAFE': '#00FF00'
    }
    
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    chart_colors = [colors.get(label, '#808080') for label in labels]
    
    fig = px.pie(
        values=values,
        names=labels,
        color=labels,
        color_discrete_map=colors,
        hole=0.4,
        title="Threat Severity Distribution"
    )
    
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}'
    )
    
    return fig


def create_timeline_chart(threat_data: List[Dict]) -> go.Figure:
    """
    Create timeline chart for threat occurrences
    
    Args:
        threat_data: List of threats with timestamps
        
    Returns:
        Plotly figure
    """
    df = pd.DataFrame(threat_data)
    
    if 'timestamp' not in df.columns:
        return go.Figure()
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.groupby([df['timestamp'].dt.date, 'threat_level']).size().reset_index(name='count')
    
    fig = px.line(
        df,
        x='timestamp',
        y='count',
        color='threat_level',
        title='Threat Timeline',
        color_discrete_map={
            'CRITICAL': '#FF0000',
            'HIGH': '#FF6B00',
            'MEDIUM': '#FFA500',
            'LOW': '#FFD700'
        }
    )
    
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Number of Threats",
        hovermode='x unified'
    )
    
    return fig


def create_geo_chart(country_data: Dict) -> go.Figure:
    """
    Create geographic distribution chart
    
    Args:
        country_data: Dictionary of country codes and threat counts
        
    Returns:
        Plotly figure
    """
    df = pd.DataFrame(list(country_data.items()), columns=['Country', 'Threats'])
    
    fig = px.bar(
        df,
        x='Country',
        y='Threats',
        title='Threats by Geographic Origin',
        color='Threats',
        color_continuous_scale='Reds',
        text='Threats'
    )
    
    fig.update_traces(
        texttemplate='%{text}',
        textposition='outside'
    )
    
    fig.update_layout(
        xaxis_title="Country",
        yaxis_title="Number of Threats",
        showlegend=False
    )
    
    return fig


def create_trend_chart(dates: List, values: Dict[str, List]) -> go.Figure:
    """
    Create multi-line trend chart
    
    Args:
        dates: List of dates
        values: Dictionary of series names and value lists
        
    Returns:
        Plotly figure
    """
    fig = go.Figure()
    
    colors = {
        'Critical': '#FF0000',
        'High': '#FF6B00',
        'Medium': '#FFA500',
        'Low': '#FFD700'
    }
    
    for series_name, series_values in values.items():
        fig.add_trace(go.Scatter(
            x=dates,
            y=series_values,
            name=series_name,
            mode='lines+markers',
            line=dict(
                color=colors.get(series_name, '#808080'),
                width=3
            ),
            marker=dict(size=8)
        ))
    
    fig.update_layout(
        title='Threat Trends Over Time',
        xaxis_title="Date",
        yaxis_title="Count",
        hovermode='x unified',
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    return fig


def create_type_distribution_chart(type_counts: Dict) -> go.Figure:
    """
    Create bar chart for IOC type distribution
    
    Args:
        type_counts: Dictionary of IOC types and counts
        
    Returns:
        Plotly figure
    """
    df = pd.DataFrame(list(type_counts.items()), columns=['Type', 'Count'])
    df = df.sort_values('Count', ascending=False)
    
    fig = px.bar(
        df,
        x='Type',
        y='Count',
        title='IOC Type Distribution',
        color='Count',
        color_continuous_scale='Blues',
        text='Count'
    )
    
    fig.update_traces(
        texttemplate='%{text}',
        textposition='outside'
    )
    
    return fig


def create_heatmap(data: pd.DataFrame, title: str = "Threat Heatmap") -> go.Figure:
    """
    Create heatmap visualization
    
    Args:
        data: DataFrame with data for heatmap
        title: Chart title
        
    Returns:
        Plotly figure
    """
    fig = go.Figure(data=go.Heatmap(
        z=data.values,
        x=data.columns,
        y=data.index,
        colorscale='Reds',
        hoverongaps=False
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title="Threat Type"
    )
    
    return fig


def create_gauge_chart(value: float, title: str = "Risk Score") -> go.Figure:
    """
    Create gauge chart for risk scoring
    
    Args:
        value: Value to display (0-100)
        title: Chart title
        
    Returns:
        Plotly figure
    """
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkred" if value > 80 else "orange" if value > 60 else "green"},
            'steps': [
                {'range': [0, 33], 'color': "lightgreen"},
                {'range': [33, 66], 'color': "lightyellow"},
                {'range': [66, 100], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    
    return fig


def create_sunburst_chart(data: List[Dict]) -> go.Figure:
    """
    Create sunburst chart for hierarchical data
    
    Args:
        data: List of dictionaries with 'labels', 'parents', and 'values'
        
    Returns:
        Plotly figure
    """
    df = pd.DataFrame(data)
    
    fig = px.sunburst(
        df,
        names='labels',
        parents='parents',
        values='values',
        title='Threat Hierarchy'
    )
    
    return fig


def create_scatter_plot(
    x_data: List,
    y_data: List,
    labels: List,
    title: str = "Threat Scatter"
) -> go.Figure:
    """
    Create scatter plot
    
    Args:
        x_data: X-axis data
        y_data: Y-axis data
        labels: Point labels
        title: Chart title
        
    Returns:
        Plotly figure
    """
    fig = go.Figure(data=go.Scatter(
        x=x_data,
        y=y_data,
        mode='markers',
        text=labels,
        marker=dict(
            size=10,
            color=y_data,
            colorscale='Reds',
            showscale=True
        )
    ))
    
    fig.update_layout(
        title=title,
        hovermode='closest'
    )
    
    return fig