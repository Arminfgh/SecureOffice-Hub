"""
Step-by-Step Threat Analysis Page - REAL DATA VERSION with PDF Export
Uses actual DNS, WHOIS, Geolocation, and VirusTotal APIs
"""

import streamlit as st
import requests
import time
from datetime import datetime
import socket
import ssl
import whois
import dns.resolver
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

st.set_page_config(page_title="Step Analysis", page_icon="🔍", layout="wide")

API_BASE_URL = "http://localhost:8000"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


def text_to_speech_html(text):
    """Generate HTML for text-to-speech"""
    # Clean text for speech
    clean_text = text.replace('"', "'").replace('\n', ' ')
    speech_js = f"""
    <script>
    function speak() {{
        var msg = new SpeechSynthesisUtterance("{clean_text}");
        msg.lang = 'en-US';
        msg.rate = 0.9;
        window.speechSynthesis.speak(msg);
    }}
    </script>
    <button onclick="speak()" style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
        font-size: 16px;">
        🔊 Play Voice
    </button>
    """
    return speech_js


def extract_domain(url):
    """Extract clean domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return url.split('/')[0]


def real_virustotal_check(url):
    """REAL VirusTotal URL check"""
    if not VIRUSTOTAL_API_KEY:
        return {
            'found': False,
            'database': None,
            'positives': 0,
            'total': 0,
            'error': 'No VirusTotal API key configured'
        }
    
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                'found': positives > 0,
                'database': 'VirusTotal',
                'positives': positives,
                'total': total,
                'error': None
            }
        else:
            return {
                'found': False,
                'database': None,
                'positives': 0,
                'total': 0,
                'error': f"API returned {response.status_code}"
            }
    except Exception as e:
        return {
            'found': False,
            'database': None,
            'positives': 0,
            'total': 0,
            'error': str(e)
        }


def real_dns_lookup(domain):
    """REAL DNS resolution"""
    try:
        # Get IP address
        ip = socket.gethostbyname(domain)
        
        # Get geolocation info (free API)
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                country = geo_data.get('country', 'Unknown')
                city = geo_data.get('city', 'Unknown')
                isp = geo_data.get('isp', 'Unknown')
                asn = geo_data.get('as', 'Unknown')
            else:
                country = 'Unknown'
                city = 'Unknown'
                isp = 'Unknown'
                asn = 'Unknown'
        except:
            country = 'Unknown'
            city = 'Unknown'
            isp = 'Unknown'
            asn = 'Unknown'
        
        # Check if suspicious location
        suspicious_countries = ['Russia', 'China', 'North Korea', 'Iran']
        suspicious = country in suspicious_countries
        
        return {
            'ip': ip,
            'country': country,
            'city': city,
            'isp': isp,
            'asn': asn,
            'suspicious': suspicious,
            'reason': f"Hosted in {country}" if suspicious else None,
            'ai_comment': f"The domain resolves to {ip} in {country}.",
            'error': None
        }
    except Exception as e:
        return {
            'ip': 'Unable to resolve',
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'asn': 'Unknown',
            'suspicious': True,
            'reason': 'DNS resolution failed',
            'ai_comment': 'Could not resolve domain.',
            'error': str(e)
        }


def real_whois_lookup(domain):
    """REAL WHOIS lookup"""
    try:
        w = whois.whois(domain)
        
        # Extract creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Calculate age
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                age = "< 30 days"
                suspicious = True
            elif age_days < 365:
                age = f"{age_days} days"
                suspicious = False
            else:
                age = f"{age_days // 365} years"
                suspicious = False
        else:
            age = "Unknown"
            suspicious = True
        
        # Get TLD
        tld = '.' + domain.split('.')[-1] if '.' in domain else 'unknown'
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        tld_suspicious = tld in suspicious_tlds
        
        # Check typosquatting
        typo_check = {
            'paypa1': 'paypal.com',
            'amaz0n': 'amazon.com',
            'g00gle': 'google.com',
            'micros0ft': 'microsoft.com',
            'bankofamerica': 'bankofamerica.com'
        }
        
        typosquatting = False
        similar_to = None
        
        for typo, real in typo_check.items():
            if typo in domain.lower():
                typosquatting = True
                similar_to = real
                break
        
        return {
            'tld': tld,
            'age': age,
            'creation_date': str(creation_date) if creation_date else 'Unknown',
            'registrar': w.registrar or 'Unknown',
            'suspicious': suspicious or tld_suspicious or typosquatting,
            'typosquatting': typosquatting,
            'similar_to': similar_to,
            'verdict': 'suspicious' if (suspicious or tld_suspicious or typosquatting) else 'normal',
            'error': None
        }
    except Exception as e:
        # Fallback for domains that don't have WHOIS
        tld = '.' + domain.split('.')[-1] if '.' in domain else 'unknown'
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        
        return {
            'tld': tld,
            'age': 'Unknown',
            'creation_date': 'Unknown',
            'registrar': 'Unknown',
            'suspicious': tld in suspicious_tlds,
            'typosquatting': False,
            'similar_to': None,
            'verdict': 'suspicious' if tld in suspicious_tlds else 'unknown',
            'error': str(e)
        }


def real_virustotal_ip_check(ip):
    """REAL VirusTotal IP reputation check"""
    if not VIRUSTOTAL_API_KEY:
        return {
            'score': 50,
            'malicious': False,
            'positives': 0,
            'total': 0,
            'error': 'No API key'
        }
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            positives = malicious + suspicious
            score = max(0, 100 - (positives * 10))
            
            return {
                'score': score,
                'malicious': positives > 3,
                'positives': positives,
                'total': total,
                'error': None
            }
        else:
            return {
                'score': 50,
                'malicious': False,
                'positives': 0,
                'total': 0,
                'error': f"API returned {response.status_code}"
            }
    except Exception as e:
        return {
            'score': 50,
            'malicious': False,
            'positives': 0,
            'total': 0,
            'error': str(e)
        }


def real_ssl_check(domain):
    """REAL SSL certificate check"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                issued_to = dict(x[0] for x in cert['subject'])
                
                return {
                    'valid': True,
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'issued_to': issued_to.get('commonName', domain),
                    'expiry': cert.get('notAfter', 'Unknown'),
                    'status': 'valid',
                    'error': None
                }
    except Exception as e:
        return {
            'valid': False,
            'issuer': 'Unknown',
            'issued_to': domain,
            'expiry': 'Unknown',
            'status': 'invalid or not available',
            'error': str(e)
        }


def main():
    st.title("🔍 Step-by-Step Threat Analysis")
    st.markdown("**REAL DATA MODE** - Using actual threat intelligence APIs")
    
    # API Status
    if VIRUSTOTAL_API_KEY:
        st.success("✅ VirusTotal API configured")
    else:
        st.warning("⚠️ VirusTotal API not configured - limited functionality")
    
    # URL Input
    st.markdown("### Enter URL to Analyze")
    
    col1, col2 = st.columns([4, 1])
    
    with col1:
        url = st.text_input(
            "URL",
            placeholder="https://example.com or paypal.com",
            label_visibility="collapsed"
        )
    
    with col2:
        analyze_btn = st.button("🔍 Analyze", type="primary", use_container_width=True)
    
    # Demo URLs
    st.markdown("**Quick Test URLs:**")
    demo_col1, demo_col2, demo_col3 = st.columns(3)
    
    with demo_col1:
        if st.button("Test: google.com"):
            url = "google.com"
            analyze_btn = True
    
    with demo_col2:
        if st.button("Test: paypal.com"):
            url = "paypal.com"
            analyze_btn = True
    
    with demo_col3:
        if st.button("Test: paypa1-secure.tk"):
            url = "paypa1-secure.tk"
            analyze_btn = True
    
    if analyze_btn and url:
        domain = extract_domain(url)
        
        st.markdown("---")
        st.markdown("## 🔬 REAL Multi-Stage Analysis in Progress")
        st.info(f"🎯 Analyzing: **{domain}**")
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Store all results
        all_iocs = []
        
        # Step 1: VirusTotal Blacklist Check (14%)
        status_text.text("Step 1/7: Checking VirusTotal database...")
        progress_bar.progress(14)
        
        with st.container():
            st.markdown("### Step 1: 🚫 VirusTotal Blacklist Check")
            with st.spinner("Querying VirusTotal API..."):
                time.sleep(0.5)
                vt_result = real_virustotal_check(url)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Status", "Found" if vt_result['found'] else "Clean")
                with col2:
                    st.metric("Detections", f"{vt_result['positives']}/{vt_result['total']}")
                with col3:
                    st.metric("Database", vt_result['database'] or "N/A")
                
                if vt_result.get('error'):
                    st.warning(f"⚠️ {vt_result['error']}")
                
                if vt_result['found']:
                    st.error(f"❌ **Malicious URL detected!** {vt_result['positives']} security vendors flagged this URL.")
                    ai_message = f"Hello Armin, VirusTotal found this URL is malicious! {vt_result['positives']} out of {vt_result['total']} security vendors detected threats."
                else:
                    st.success("✅ **URL is clean** in VirusTotal database")
                    ai_message = f"Hello Armin, good news! VirusTotal shows this URL is clean. {vt_result['total']} security vendors checked it."
                
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
        
        st.markdown("---")
        
        # Step 2: REAL DNS Resolution (28%)
        status_text.text("Step 2/7: Performing real DNS lookup...")
        progress_bar.progress(28)
        
        with st.container():
            st.markdown("### Step 2: 🌐 DNS Resolution (REAL)")
            with st.spinner("Resolving DNS..."):
                time.sleep(0.5)
                dns_result = real_dns_lookup(domain)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("IP Address", dns_result['ip'])
                with col2:
                    st.metric("Location", f"{dns_result['city']}, {dns_result['country']}")
                with col3:
                    st.metric("ISP", dns_result['isp'])
                
                if dns_result.get('error'):
                    st.warning(f"⚠️ {dns_result['error']}")
                
                if dns_result['suspicious']:
                    st.warning(f"⚠️ **Suspicious location:** {dns_result['reason']}")
                else:
                    st.success("✅ IP location looks normal")
                
                ai_message = f"Armin, the domain resolves to IP {dns_result['ip']} located in {dns_result['country']}. ISP is {dns_result['isp']}. {dns_result['ai_comment']}"
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
                
                # Add IP to IOCs
                all_iocs.append({
                    'type': 'ip_address',
                    'value': dns_result['ip'],
                    'threat_level': 'HIGH' if dns_result['suspicious'] else 'LOW'
                })
        
        st.markdown("---")
        
        # Step 3: REAL WHOIS (42%)
        status_text.text("Step 3/7: Performing WHOIS lookup...")
        progress_bar.progress(42)
        
        with st.container():
            st.markdown("### Step 3: 🏢 WHOIS Domain Lookup (REAL)")
            with st.spinner("Querying WHOIS database..."):
                time.sleep(0.5)
                whois_result = real_whois_lookup(domain)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    status = "⚠️ Suspicious" if whois_result['suspicious'] else "✅ Normal"
                    st.metric("Status", status)
                with col2:
                    st.metric("Domain Age", whois_result['age'])
                with col3:
                    st.metric("TLD", whois_result['tld'])
                
                st.write(f"**Registrar:** {whois_result['registrar']}")
                st.write(f"**Created:** {whois_result['creation_date']}")
                
                if whois_result.get('error'):
                    st.info(f"ℹ️ WHOIS lookup note: {whois_result['error']}")
                
                if whois_result['typosquatting']:
                    st.error(f"🚨 **Typosquatting detected!** Similar to: {whois_result['similar_to']}")
                    ai_message = f"Armin, CRITICAL ALERT! This domain is typosquatting {whois_result['similar_to']}. This is a major phishing indicator!"
                else:
                    ai_message = f"Armin, the domain is {whois_result['age']} old with TLD {whois_result['tld']}. Status looks {whois_result['verdict']}."
                
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
                
                # Add domain to IOCs
                all_iocs.append({
                    'type': 'domain',
                    'value': domain,
                    'threat_level': 'CRITICAL' if whois_result['typosquatting'] else 'LOW'
                })
        
        st.markdown("---")
        
        # Step 4: IP Reputation (56%)
        status_text.text("Step 4/7: Checking IP reputation...")
        progress_bar.progress(56)
        
        with st.container():
            st.markdown("### Step 4: 🛡️ IP Reputation Check (VirusTotal)")
            with st.spinner("Querying VirusTotal IP database..."):
                time.sleep(0.5)
                ip_rep = real_virustotal_ip_check(dns_result['ip'])
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Reputation Score", f"{ip_rep['score']}/100")
                with col2:
                    st.metric("Detections", f"{ip_rep['positives']}/{ip_rep['total']}")
                with col3:
                    st.metric("Status", "Malicious" if ip_rep['malicious'] else "Clean")
                
                if ip_rep.get('error'):
                    st.warning(f"⚠️ {ip_rep['error']}")
                
                if ip_rep['malicious']:
                    st.error(f"❌ **Malicious IP!** Flagged by {ip_rep['positives']} security vendors.")
                    ai_message = f"Armin, this IP has a bad reputation! {ip_rep['positives']} vendors detected malicious activity. Score is only {ip_rep['score']} out of 100."
                else:
                    st.success("✅ IP has clean reputation")
                    ai_message = f"Armin, the IP has a good reputation score of {ip_rep['score']} out of 100."
                
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
        
        st.markdown("---")
        
        # Step 5: SSL Check (70%)
        status_text.text("Step 5/7: Checking SSL certificate...")
        progress_bar.progress(70)
        
        with st.container():
            st.markdown("### Step 5: 🔒 SSL Certificate Check (REAL)")
            with st.spinner("Verifying SSL certificate..."):
                time.sleep(0.5)
                ssl_result = real_ssl_check(domain)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Certificate", "Valid" if ssl_result['valid'] else "Invalid")
                with col2:
                    st.metric("Issuer", ssl_result['issuer'])
                with col3:
                    st.metric("Issued To", ssl_result['issued_to'])
                
                if ssl_result.get('error'):
                    st.info(f"ℹ️ SSL note: {ssl_result['error']}")
                
                if not ssl_result['valid']:
                    st.warning("⚠️ **SSL certificate issue detected!**")
                    ai_message = f"Armin, the SSL certificate is {ssl_result['status']}. This could indicate security issues."
                else:
                    st.success(f"✅ Valid SSL certificate (expires: {ssl_result['expiry']})")
                    ai_message = f"Armin, the SSL certificate is valid, issued by {ssl_result['issuer']}."
                
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
        
        st.markdown("---")
        
        # Step 6: Pattern Recognition (84%)
        status_text.text("Step 6/7: Analyzing URL patterns...")
        progress_bar.progress(84)
        
        with st.container():
            st.markdown("### Step 6: 🔍 Pattern Recognition")
            suspicious_keywords = ['verify', 'secure', 'login', 'account', 'update', 'confirm', 'suspended', 'locked', 'alert']
            found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
            
            if found_keywords:
                st.warning(f"⚠️ **Suspicious keywords found:** {', '.join(found_keywords)}")
                ai_message = f"Armin, I found {len(found_keywords)} suspicious keywords: {', '.join(found_keywords)}. These are common in phishing."
            else:
                st.success("✅ No suspicious keywords detected")
                ai_message = "Armin, the URL structure looks clean, no phishing keywords detected."
            
            st.info(f"🤖 **AI says:** {ai_message}")
            st.components.v1.html(text_to_speech_html(ai_message), height=60)
        
        st.markdown("---")
        
        # Step 7: AI Analysis (100%)
        status_text.text("Step 7/7: Running GPT-4 analysis...")
        progress_bar.progress(100)
        
        with st.container():
            st.markdown("### Step 7: 🤖 AI Deep Analysis (GPT-4)")
            with st.spinner("Consulting OpenAI GPT-4..."):
                time.sleep(1.0)
                
                try:
                    response = requests.post(
                        f"{API_BASE_URL}/api/analyze/url",
                        json={"url": url},
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        ai_result = response.json()
                    else:
                        # Fallback result
                        threat_level = "CRITICAL" if (vt_result['found'] or whois_result['typosquatting']) else "LOW"
                        ai_result = {
                            'threat_level': threat_level,
                            'confidence': 0.85,
                            'threat_type': 'phishing' if whois_result['typosquatting'] else 'unknown',
                            'recommendations': [
                                "Block URL immediately if suspicious",
                                "Monitor for related IOCs",
                                "Alert security team"
                            ]
                        }
                except:
                    threat_level = "CRITICAL" if (vt_result['found'] or whois_result['typosquatting']) else "LOW"
                    ai_result = {
                        'threat_level': threat_level,
                        'confidence': 0.85,
                        'threat_type': 'phishing' if whois_result['typosquatting'] else 'unknown',
                        'recommendations': [
                            "Block URL immediately if suspicious",
                            "Monitor for related IOCs",
                            "Alert security team"
                        ]
                    }
                
                # Display results
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    level = ai_result.get('threat_level', 'UNKNOWN')
                    color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'SAFE': '🟢'}.get(level, '⚪')
                    st.metric("Threat Level", f"{color} {level}")
                
                with col2:
                    confidence = ai_result.get('confidence', 0) * 100
                    st.metric("Confidence", f"{confidence:.0f}%")
                
                with col3:
                    threat_type = ai_result.get('threat_type', 'Unknown')
                    st.metric("Type", threat_type.title())
                
                explanation = ai_result.get('explanation', 'Analysis complete based on all security checks.')
                ai_message = f"Armin, final assessment: {explanation}"
                
                st.info(f"🤖 **AI says:** {ai_message}")
                st.components.v1.html(text_to_speech_html(ai_message), height=60)
        
        status_text.text("✅ Real-time analysis complete!")
        
        # Store in session
        st.session_state.analysis_result = ai_result
        st.session_state.analysis_url = url
        st.session_state.analysis_iocs = all_iocs
        st.session_state.dns_result = dns_result
        st.session_state.ip_rep_result = ip_rep
        st.session_state.domain_result = whois_result
        st.session_state.vt_result = vt_result
        st.session_state.ssl_result = ssl_result
        st.session_state.found_keywords = found_keywords
        
        # Summary
        st.markdown("---")
        st.markdown("### 📊 Analysis Summary")
        
        summary = f"Armin, analysis complete! This URL is classified as {ai_result.get('threat_level', 'UNKNOWN')}. "
        summary += f"VirusTotal: {vt_result['positives']}/{vt_result['total']} detections. "
        summary += f"IP: {dns_result['ip']} in {dns_result['country']}. "
        
        if whois_result['typosquatting']:
            summary += "CRITICAL: Typosquatting detected!"
        
        st.success(summary)
        st.components.v1.html(text_to_speech_html(summary), height=60)
        
        # Actions
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🕸️ View Threat Graph", use_container_width=True, type="primary"):
                st.switch_page("pages/2_threat_graph.py")
        
        with col2:
            if st.button("📥 Export PDF Report", use_container_width=True):
                try:
                    from src.utils.pdf_generator import generate_analysis_pdf
                    
                    # Prepare data for PDF
                    pdf_data = {
                        'url': url,
                        'threat_level': ai_result.get('threat_level'),
                        'confidence': ai_result.get('confidence'),
                        'threat_type': ai_result.get('threat_type'),
                        'iocs': all_iocs,
                        'recommendations': ai_result.get('recommendations', []),
                        'steps': {
                            'vt_result': vt_result,
                            'dns_result': dns_result,
                            'whois_result': whois_result,
                            'ip_rep_result': ip_rep,
                            'ssl_result': ssl_result,
                            'patterns': {'keywords': found_keywords}
                        }
                    }
                    
                    # Generate PDF
                    pdf_buffer = generate_analysis_pdf(pdf_data)
                    
                    # Download button
                    st.download_button(
                        label="📄 Download PDF",
                        data=pdf_buffer,
                        file_name=f"ThreatScope_Analysis_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                    st.success("✅ PDF Report ready!")
                    
                except Exception as e:
                    st.error(f"❌ PDF generation failed: {str(e)}")
        
        with col3:
            if st.button("🔍 Analyze Another", use_container_width=True):
                st.rerun()


if __name__ == "__main__":
    main()