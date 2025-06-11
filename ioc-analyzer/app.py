from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import requests
import json
import time
import os
import shutil
import atexit
import sys
from datetime import datetime
import hashlib
import re

# PyInstaller compatibility
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

app = Flask(__name__, 
           template_folder=resource_path('templates'),
           static_folder=resource_path('static'))
app.secret_key = 'your-secret-key-change-this'

# Configuration - Use current directory for config and results
CONFIG_FILE = 'config.json'
RESULTS_DIR = 'results'

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

def cleanup_results():
    """Clean up results folder when app closes"""
    try:
        if os.path.exists(RESULTS_DIR):
            shutil.rmtree(RESULTS_DIR)
            print("Results folder cleaned up successfully")
    except Exception as e:
        print(f"Error cleaning up results folder: {e}")

# Register cleanup function to run when app closes
atexit.register(cleanup_results)

class IOCAnalyzer:
    def __init__(self):
        self.api_key = self.load_api_key()
        self.base_url = "https://www.virustotal.com/vtapi/v2/"
    
    def load_api_key(self):
        """Load API key from config file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    return config.get('vt_api_key', '')
        except Exception as e:
            print(f"Error loading config: {e}")
        return ''
    
    def save_api_key(self, api_key):
        """Save API key to config file"""
        try:
            config = {'vt_api_key': api_key}
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            self.api_key = api_key
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def validate_ioc(self, ioc, ioc_type):
        """Validate IOC format"""
        if ioc_type == 'hash':
            # MD5, SHA1, SHA256
            if re.match(r'^[a-fA-F0-9]{32}$', ioc) or \
               re.match(r'^[a-fA-F0-9]{40}$', ioc) or \
               re.match(r'^[a-fA-F0-9]{64}$', ioc):
                return True
        elif ioc_type == 'ip':
            # Basic IP validation
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ioc):
                return True
        elif ioc_type == 'domain':
            # Basic domain validation
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
                return True
        elif ioc_type == 'url':
            # Basic URL validation
            if re.match(r'^https?://', ioc):
                return True
        return False
    
    def format_scan_date(self, scan_date):
        """Format scan date for display"""
        if not scan_date:
            return 'N/A'
        try:
            # VirusTotal returns dates in format: "2023-01-01 12:00:00"
            dt = datetime.strptime(scan_date, '%Y-%m-%d %H:%M:%S')
            return dt.strftime('%Y-%m-%d %H:%M')
        except:
            return scan_date
    
    def analyze_hash(self, hash_value):
        """Analyze file hash using VirusTotal API"""
        url = f"{self.base_url}file/report"
        params = {
            'apikey': self.api_key,
            'resource': hash_value
        }
        
        try:
            response = requests.get(url, params=params)
            result = response.json()
            
            print(f"Hash API Response: {result}")  # Debug output
            
            # Handle VirusTotal response format
            if result.get('response_code') == 1:
                # File found in VirusTotal database
                return {
                    'response_code': result.get('response_code'),
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'scan_date': self.format_scan_date(result.get('scan_date')),
                    'permalink': result.get('permalink'),
                    'md5': result.get('md5'),
                    'sha1': result.get('sha1'),
                    'sha256': result.get('sha256')
                }
            elif result.get('response_code') == 0:
                # File not found in database
                return {
                    'response_code': 0,
                    'positives': 0,
                    'total': 0,
                    'scan_date': 'Not scanned',
                    'permalink': None,
                    'message': 'File not found in VirusTotal database'
                }
            else:
                return {'error': result.get('verbose_msg', 'Unknown error')}
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_ip(self, ip_address):
        """Analyze IP address using VirusTotal API"""
        url = f"{self.base_url}ip-address/report"
        params = {
            'apikey': self.api_key,
            'ip': ip_address
        }
        
        try:
            response = requests.get(url, params=params)
            result = response.json()
            
            print(f"IP API Response: {result}")  # Debug output
            
            if result.get('response_code') == 1:
                detected_urls = result.get('detected_urls', [])
                positives = len([url for url in detected_urls if url.get('positives', 0) > 0])
                
                return {
                    'response_code': result.get('response_code'),
                    'positives': positives,
                    'total': len(detected_urls) if detected_urls else 0,
                    'scan_date': self.format_scan_date(result.get('scan_date')),
                    'permalink': f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    'country': result.get('country'),
                    'as_owner': result.get('as_owner')
                }
            else:
                return {
                    'response_code': 0,
                    'positives': 0,
                    'total': 0,
                    'scan_date': 'Not scanned',
                    'permalink': f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                    'message': 'IP not found in VirusTotal database'
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_domain(self, domain):
        """Analyze domain using VirusTotal API"""
        url = f"{self.base_url}domain/report"
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        try:
            response = requests.get(url, params=params)
            result = response.json()
            
            print(f"Domain API Response: {result}")  # Debug output
            
            if result.get('response_code') == 1:
                detected_urls = result.get('detected_urls', [])
                positives = len([url for url in detected_urls if url.get('positives', 0) > 0])
                
                return {
                    'response_code': result.get('response_code'),
                    'positives': positives,
                    'total': len(detected_urls) if detected_urls else 0,
                    'scan_date': self.format_scan_date(result.get('scan_date')),
                    'permalink': f"https://www.virustotal.com/gui/domain/{domain}",
                    'whois_timestamp': result.get('whois_timestamp')
                }
            else:
                return {
                    'response_code': 0,
                    'positives': 0,
                    'total': 0,
                    'scan_date': 'Not scanned',
                    'permalink': f"https://www.virustotal.com/gui/domain/{domain}",
                    'message': 'Domain not found in VirusTotal database'
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_url(self, url_to_check):
        """Analyze URL using VirusTotal API"""
        url = f"{self.base_url}url/report"
        params = {
            'apikey': self.api_key,
            'resource': url_to_check
        }
        
        try:
            response = requests.get(url, params=params)
            result = response.json()
            
            print(f"URL API Response: {result}")  # Debug output
            
            if result.get('response_code') == 1:
                return {
                    'response_code': result.get('response_code'),
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'scan_date': self.format_scan_date(result.get('scan_date')),
                    'permalink': result.get('permalink')
                }
            elif result.get('response_code') == 0:
                return {
                    'response_code': 0,
                    'positives': 0,
                    'total': 0,
                    'scan_date': 'Not scanned',
                    'permalink': None,
                    'message': 'URL not found in VirusTotal database'
                }
            else:
                return {'error': result.get('verbose_msg', 'Unknown error')}
                
        except Exception as e:
            return {'error': str(e)}

analyzer = IOCAnalyzer()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html', api_key=analyzer.api_key)

@app.route('/save_settings', methods=['POST'])
def save_settings():
    """Save API key settings"""
    api_key = request.form.get('api_key', '').strip()
    
    if not api_key:
        flash('API key cannot be empty', 'error')
        return redirect(url_for('settings'))
    
    if analyzer.save_api_key(api_key):
        flash('Settings saved successfully', 'success')
    else:
        flash('Error saving settings', 'error')
    
    return redirect(url_for('settings'))

@app.route('/analyze', methods=['POST'])
def analyze_iocs():
    """Analyze IOCs in bulk"""
    if not analyzer.api_key:
        return jsonify({'error': 'API key not configured. Please set it in settings.'}), 400
    
    data = request.get_json()
    iocs = data.get('iocs', [])
    
    if not iocs:
        return jsonify({'error': 'No IOCs provided'}), 400
    
    results = []
    
    for i, ioc_data in enumerate(iocs):
        ioc = ioc_data.get('value', '').strip()
        ioc_type = ioc_data.get('type', '').lower()
        
        print(f"Analyzing IOC {i+1}/{len(iocs)}: {ioc} ({ioc_type})")
        
        if not analyzer.validate_ioc(ioc, ioc_type):
            results.append({
                'ioc': ioc,
                'type': ioc_type,
                'error': 'Invalid IOC format',
                'analyzed_at': datetime.now().isoformat()
            })
            continue
        
        # Analyze based on type
        if ioc_type == 'hash':
            result = analyzer.analyze_hash(ioc)
        elif ioc_type == 'ip':
            result = analyzer.analyze_ip(ioc)
        elif ioc_type == 'domain':
            result = analyzer.analyze_domain(ioc)
        elif ioc_type == 'url':
            result = analyzer.analyze_url(ioc)
        else:
            result = {'error': 'Unsupported IOC type'}
        
        # Add metadata
        result['ioc'] = ioc
        result['type'] = ioc_type
        result['analyzed_at'] = datetime.now().isoformat()
        
        results.append(result)
        
        # Rate limiting - VirusTotal free API allows 4 requests per minute
        if i < len(iocs) - 1:  # Don't sleep after the last request
            print(f"Waiting 15 seconds before next request...")
            time.sleep(15)  # 15 seconds between requests
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"analysis_{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        print(f"Error saving results: {e}")
    
    return jsonify({
        'results': results,
        'saved_to': filename
    })

def open_browser():
    """Open browser after a short delay"""
    import webbrowser
    import threading
    
    def delayed_open():
        time.sleep(1.5)  # Wait for Flask to start
        webbrowser.open('http://127.0.0.1:5000')
    
    threading.Thread(target=delayed_open).start()

if __name__ == '__main__':
    try:
        print("Starting IOC Analyzer...")
        print("Opening browser in 1.5 seconds...")
        open_browser()
        app.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        cleanup_results()