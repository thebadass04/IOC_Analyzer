# IOC_Analyzer

SOC Team IOC Analysis Tool powered by VirusTotal API

## Installation

1. Install requirements: `pip install -r requirements.txt`
2. Start the application: `python app.py`
3. Open browser to: `http://127.0.0.1:5000`

## Building Executable

1. Install PyInstaller: `pip install pyinstaller`
2. Build executable: `pyinstaller --clean ioc_analyzer.spec`
3. Find executable in: `dist/IOC_Analyzer.exe`

## Features

- Bulk IOC analysis (hashes, IPs, domains, URLs)
- VirusTotal API integration
- Modern web interface with PWC colors
- Automatic results export
- Real-time analysis progress

## Configuration

1. Go to Settings page
2. Enter your VirusTotal API key
3. Start analyzing IOCs

