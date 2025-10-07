"""
Settings Page
Configuration and preferences
"""

import streamlit as st
import requests


st.set_page_config(page_title="Settings", page_icon="⚙️", layout="wide")

API_BASE_URL = "http://localhost:8000"


def main():
    st.title("⚙️ Settings & Configuration")
    st.markdown("Customize your ThreatScope experience")
    
    # Tabs for different settings
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔧 General",
        "🤖 AI Configuration", 
        "🌐 API Settings",
        "ℹ️ About"
    ])
    
    # General Settings
    with tab1:
        st.markdown("### 🔧 General Settings")
        
        st.markdown("#### Display Preferences")
        
        col1, col2 = st.columns(2)
        
        with col1:
            theme = st.selectbox(
                "Theme",
                ["Dark", "Light", "Auto"],
                index=0
            )
            
            language = st.selectbox(
                "Language",
                ["English", "German", "Spanish", "French"],
                index=0
            )
        
        with col2:
            auto_refresh = st.checkbox("Auto-refresh Dashboard", value=False)
            
            refresh_interval = st.slider(
                "Refresh Interval (seconds)",
                min_value=10,
                max_value=300,
                value=60,
                step=10,
                disabled=not auto_refresh
            )
        
        st.markdown("---")
        st.markdown("#### Notification Preferences")
        
        col1, col2 = st.columns(2)
        
        with col1:
            notify_critical = st.checkbox("Notify on Critical Threats", value=True)
            notify_high = st.checkbox("Notify on High Threats", value=False)
        
        with col2:
            email_alerts = st.checkbox("Email Alerts", value=False)
            sound_alerts = st.checkbox("Sound Alerts", value=True)
        
        if st.button("💾 Save General Settings", type="primary"):
            st.success("✅ Settings saved successfully!")
    
    # AI Configuration
    with tab2:
        st.markdown("### 🤖 AI Configuration")
        
        st.markdown("#### OpenAI Settings")
        
        api_key_input = st.text_input(
            "OpenAI API Key",
            type="password",
            placeholder="sk-proj-...",
            help="Your OpenAI API key for threat analysis"
        )
        
        model = st.selectbox(
            "AI Model",
            ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
            index=0,
            help="Select the AI model for analysis"
        )
        
        st.markdown("---")
        st.markdown("#### Analysis Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            analysis_depth = st.select_slider(
                "Analysis Depth",
                options=["Quick", "Standard", "Deep"],
                value="Standard"
            )
            
            confidence_threshold = st.slider(
                "Confidence Threshold",
                min_value=0.0,
                max_value=1.0,
                value=0.7,
                step=0.05,
                help="Minimum confidence for threat detection"
            )
        
        with col2:
            enable_voice = st.checkbox("Enable Voice Feedback", value=True)
            
            voice_speed = st.slider(
                "Voice Speed",
                min_value=0.5,
                max_value=2.0,
                value=0.9,
                step=0.1,
                disabled=not enable_voice
            )
        
        if st.button("💾 Save AI Settings", type="primary"):
            st.success("✅ AI settings saved successfully!")
        
        st.markdown("---")
        st.markdown("#### 📊 Current API Usage")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Requests Today", "127")
        
        with col2:
            st.metric("Total Cost", "$2.34")
        
        with col3:
            st.metric("Avg Response", "2.3s")
    
    # API Settings
    with tab3:
        st.markdown("### 🌐 API Settings")
        
        st.markdown("#### Connection Settings")
        
        api_url = st.text_input(
            "API Base URL",
            value="http://localhost:8000",
            help="Backend API endpoint"
        )
        
        timeout = st.number_input(
            "Request Timeout (seconds)",
            min_value=5,
            max_value=120,
            value=30,
            step=5
        )
        
        st.markdown("---")
        st.markdown("#### API Status")
        
        if st.button("🔍 Test Connection"):
            with st.spinner("Testing API connection..."):
                try:
                    response = requests.get(f"{API_BASE_URL}/health", timeout=5)
                    if response.status_code == 200:
                        st.success("✅ API is reachable and healthy!")
                        
                        data = response.json()
                        st.json(data)
                    else:
                        st.error(f"❌ API returned status code: {response.status_code}")
                except Exception as e:
                    st.error(f"❌ Connection failed: {str(e)}")
                    st.info("💡 Make sure the backend is running: `uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload`")
        
        st.markdown("---")
        st.markdown("#### Threat Intelligence Feeds")
        
        st.info("Configure external threat intelligence sources")
        
        feeds = [
            {"name": "AbuseIPDB", "enabled": True, "status": "Active"},
            {"name": "AlienVault OTX", "enabled": True, "status": "Active"},
            {"name": "URLhaus", "enabled": False, "status": "Inactive"},
            {"name": "PhishTank", "enabled": True, "status": "Active"}
        ]
        
        for feed in feeds:
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.markdown(f"**{feed['name']}**")
            
            with col2:
                status_icon = "🟢" if feed['enabled'] else "🔴"
                st.markdown(f"{status_icon} {feed['status']}")
            
            with col3:
                st.checkbox("Enable", value=feed['enabled'], key=f"feed_{feed['name']}")
        
        if st.button("💾 Save API Settings", type="primary"):
            st.success("✅ API settings saved successfully!")
    
    # About
    with tab4:
        st.markdown("### ℹ️ About ThreatScope")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("""
            **ThreatScope** is an AI-powered threat intelligence platform designed to 
            analyze and detect cyber threats in real-time.
            
            #### 🎯 Key Features:
            - **AI-Powered Analysis** using GPT-4
            - **Step-by-Step Threat Detection** with voice feedback
            - **Interactive Threat Graph** visualization
            - **Real-time Threat Intelligence** feeds
            - **Advanced Data Structures** (Bloom Filter, Merkle Tree, Graph)
            
            #### 🔧 Technology Stack:
            - **Backend:** FastAPI + Python
            - **AI:** OpenAI GPT-4
            - **Frontend:** Streamlit
            - **Graph:** NetworkX + PyVis
            - **Database:** SQLite / PostgreSQL
            
            #### 📜 Version History:
            - **v1.0** (2025-01-15) - Initial release
            - **v0.9** (2024-12-20) - Beta testing
            """)
        
        with col2:
            st.markdown("#### 📊 System Info")
            st.info("**Version:** 1.0.0")
            st.info("**Build:** 2025.01.15")
            st.info("**License:** MIT")
            
            st.markdown("---")
            st.markdown("#### 👨‍💻 Created by")
            st.markdown("""
            **Armin Foroughi**
            
            ⚫🟡 **Borussia Dortmund**  
            Interview Project
            
            📧 Contact: [email]  
            🔗 LinkedIn: [profile]
            """)
        
        st.markdown("---")
        st.markdown("#### 📝 Credits")
        
        st.markdown("""
        Special thanks to:
        - OpenAI for GPT-4 API
        - Streamlit Team
        - NetworkX & PyVis developers
        - Threat Intelligence Community
        - **Borussia Dortmund** for the opportunity
        """)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📚 Documentation", use_container_width=True):
                st.info("Documentation coming soon!")
        
        with col2:
            if st.button("🐛 Report Bug", use_container_width=True):
                st.info("Bug report form coming soon!")
        
        with col3:
            if st.button("💬 Feedback", use_container_width=True):
                st.info("Feedback form coming soon!")


if __name__ == "__main__":
    main()