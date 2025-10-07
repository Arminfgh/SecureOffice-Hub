# 🚀 Setup Guide - Real API Integration

## ✅ Was ist jetzt ECHT?

### 100% Real Data:
- ✅ **DNS Lookup** - Echter DNS Resolver
- ✅ **IP Geolocation** - ip-api.com (kostenlos, kein Key)
- ✅ **WHOIS Lookup** - Echte Domain-Daten
- ✅ **VirusTotal** - Malware/Phishing Datenbank
- ✅ **SSL Certificate Check** - Echte Zertifikat-Prüfung
- ✅ **GPT-4 Analysis** - OpenAI (bereits konfiguriert)

## 📋 Installation Steps

### 1. Neue Dependencies installieren

```bash
# Im ThreatScope Verzeichnis
pip install -r requirements.txt
```

Neue Packages:
- `dnspython` - DNS lookups
- `python-whois` - WHOIS queries
- (ip-api.com wird via REST API genutzt - kein Package nötig)

### 2. VirusTotal API Key holen (KOSTENLOS!)

1. Gehe zu: https://www.virustotal.com/gui/join-us
2. Registriere dich mit Email (KEINE Firma nötig!)
3. Bestätige Email
4. Gehe zu: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
5. Kopiere deinen API Key

**Free Tier Limits:**
- 4 requests/minute
- 500 requests/day
- ✅ Reicht für Demo/Interview!

### 3. .env Datei aktualisieren

```bash
# Öffne .env (nicht .env.example!)
notepad .env
```

Füge hinzu:
```env
VIRUSTOTAL_API_KEY="dein-key-hier"
```

### 4. Neue Analysis-Datei ersetzen

Ersetze: `src/dashboard/pages/1_step_analysis.py`

Mit dem neuen Code aus dem Artifact oben.

### 5. Backend & Dashboard neu starten

```bash
# Terminal 1 - Backend
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 - Dashboard
streamlit run src/dashboard/app.py
```

## 🧪 Test URLs

### Legitime URLs (sollten CLEAN sein):
```
google.com
paypal.com
amazon.com
microsoft.com
```

### Verdächtige URLs:
```
paypa1-secure.tk
bankofamerica-alert.xyz
amaz0n-login.ga
```

## 📊 Was du jetzt siehst:

### Step 1: VirusTotal Check
- **Echt:** VirusTotal API wird abgefragt
- **Zeigt:** X/Y security vendors detected threats

### Step 2: DNS Resolution
- **Echt:** Python socket macht DNS lookup
- **Zeigt:** Echte IP-Adresse
- **Echt:** ip-api.com gibt Geolocation (Land, Stadt, ISP)

### Step 3: WHOIS Lookup
- **Echt:** WHOIS Datenbank wird abgefragt
- **Zeigt:** 
  - Domain-Alter
  - Registrar
  - Erstellungsdatum
  - Typosquatting-Erkennung

### Step 4: IP Reputation
- **Echt:** VirusTotal IP database
- **Zeigt:** Reputation Score, Detections

### Step 5: SSL Certificate
- **Echt:** SSL Zertifikat wird geprüft
- **Zeigt:** Issuer, Expiry Date, Validity

### Step 6: Pattern Recognition
- **Local:** Keyword-Analyse

### Step 7: GPT-4 Analysis
- **Echt:** OpenAI API (bereits konfiguriert)

## ⚠️ Wichtige Hinweise

### Rate Limits beachten:

**VirusTotal Free:**
- 4 requests/minute
- Bei zu vielen Anfragen: Warte 15 Sekunden

### Fallback bei Errors:

Der Code hat Fallbacks wenn:
- Kein API Key konfiguriert
- Rate Limit erreicht
- Domain nicht auflösbar
- WHOIS nicht verfügbar

→ System zeigt **immer ein Ergebnis**, auch bei Fehlern!

## 🎯 Für Dortmund Interview

**Demo-Ablauf:**

1. **Legitime URL testen:**
   - `google.com` → Alles CLEAN ✅
   - Zeigt: Echte IP, USA, Valid SSL

2. **Phishing URL testen:**
   - `paypa1-secure.tk` → CRITICAL ⚠️
   - Zeigt: VirusTotal detections, Typosquatting

3. **Graph zeigen:**
   - Alle echten IOCs verknüpft
   - IP → Domain → Malware

**Wichtig zu sagen:**
> "Das System nutzt VirusTotal, DNS, WHOIS und andere Threat Intelligence APIs für Echtzeit-Analyse"

## 🐛 Troubleshooting

### "No VirusTotal API key configured"
→ Füge Key in `.env` hinzu

### "DNS resolution failed"
→ Domain existiert nicht oder ist nicht erreichbar

### "Rate limit exceeded"
→ Warte 1 Minute, dann erneut versuchen

### WHOIS Fehler
→ Manche Domains haben kein öffentliches WHOIS (z.B. .tk)
→ Code hat Fallback

## ✅ Checklist für Interview

- [ ] `pip install -r requirements.txt` ausgeführt
- [ ] VirusTotal API Key in `.env` eingetragen
- [ ] Backend läuft: `http://localhost:8000/health`
- [ ] Dashboard läuft: `http://localhost:8501`
- [ ] Test mit `google.com` erfolgreich
- [ ] Test mit `paypa1-secure.tk` zeigt CRITICAL

**Jetzt bist du ready für Dortmund! 🟡⚫**