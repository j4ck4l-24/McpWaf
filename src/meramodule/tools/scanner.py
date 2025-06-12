import subprocess
import requests
import json
import tempfile
import os
from typing import Dict, List, Any
from ..config import Config

class AdvancedScanner:
    def __init__(self):
        self.config = Config()
        self.session = requests.Session()
    
    def run_sqlmap(self, url: str, parameters: List[str] = None) -> Dict[str, Any]:
        results = []
        
        if parameters:
            for param in parameters:
                target_url = f"{url}?{param}=1"
                cmd = [
                    'python3', self.config.SQLMAP_PATH,
                    '-u', target_url,
                    '--batch',
                    '--level=3',
                    '--risk=2',
                    '--output-dir=/tmp/sqlmap_output',
                    '--format=JSON'
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if "might be injectable" in result.stdout or "Parameter:" in result.stdout:
                        results.append({
                            'parameter': param,
                            'url': target_url,
                            'vulnerable': True,
                            'tool_output': result.stdout,
                            'vulnerability_type': 'SQLi',
                            'risk_level': 'Critical'
                        })
                except subprocess.TimeoutExpired:
                    results.append({
                        'parameter': param,
                        'url': target_url,
                        'vulnerable': False,
                        'error': 'Timeout',
                        'vulnerability_type': 'SQLi'
                    })
                except Exception as e:
                    results.append({
                        'parameter': param,
                        'url': target_url,
                        'vulnerable': False,
                        'error': str(e),
                        'vulnerability_type': 'SQLi'
                    })
        else:
            cmd = [
                'python3', self.config.SQLMAP_PATH,
                '-u', url,
                '--crawl=2',
                '--batch',
                '--level=3',
                '--risk=2'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append({
                    'url': url,
                    'vulnerable': "might be injectable" in result.stdout,
                    'tool_output': result.stdout,
                    'vulnerability_type': 'SQLi',
                    'risk_level': 'Critical' if "might be injectable" in result.stdout else 'None'
                })
            except Exception as e:
                results.append({
                    'url': url,
                    'vulnerable': False,
                    'error': str(e),
                    'vulnerability_type': 'SQLi'
                })
        
        return {'tool': 'sqlmap', 'results': results}
    
    def run_xsstrike(self, url: str, parameters: List[str] = None) -> Dict[str, Any]:
        results = []
        
        if parameters:
            for param in parameters:
                target_url = f"{url}?{param}=test"
                cmd = [
                    'python3', self.config.XSSTRIKE_PATH,
                    '-u', target_url,
                    '--crawl',
                    '--fuzzer'
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    
                    if "XSS" in result.stdout or "vulnerable" in result.stdout.lower():
                        results.append({
                            'parameter': param,
                            'url': target_url,
                            'vulnerable': True,
                            'tool_output': result.stdout,
                            'vulnerability_type': 'XSS',
                            'risk_level': 'Medium'
                        })
                    else:
                        results.append({
                            'parameter': param,
                            'url': target_url,
                            'vulnerable': False,
                            'vulnerability_type': 'XSS'
                        })
                except Exception as e:
                    results.append({
                        'parameter': param,
                        'url': target_url,
                        'vulnerable': False,
                        'error': str(e),
                        'vulnerability_type': 'XSS'
                    })
        else:
            cmd = [
                'python3', self.config.XSSTRIKE_PATH,
                '-u', url,
                '--crawl'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                results.append({
                    'url': url,
                    'vulnerable': "XSS" in result.stdout,
                    'tool_output': result.stdout,
                    'vulnerability_type': 'XSS',
                    'risk_level': 'Medium' if "XSS" in result.stdout else 'None'
                })
            except Exception as e:
                results.append({
                    'url': url,
                    'vulnerable': False,
                    'error': str(e),
                    'vulnerability_type': 'XSS'
                })
        
        return {'tool': 'xsstrike', 'results': results}
    
    def run_tplmap(self, url: str, parameters: List[str] = None) -> Dict[str, Any]:
        results = []
        
        if parameters:
            for param in parameters:
                target_url = f"{url}?{param}=test"
                cmd = [
                    'python3', self.config.TPLMAP_PATH,
                    '-u', target_url,
                    '--engine', 'all',
                    '--technique', 'R'
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    
                    if "SSTI" in result.stdout or "Template injection" in result.stdout:
                        results.append({
                            'parameter': param,
                            'url': target_url,
                            'vulnerable': True,
                            'tool_output': result.stdout,
                            'vulnerability_type': 'SSTI',
                            'risk_level': 'High'
                        })
                    else:
                        results.append({
                            'parameter': param,
                            'url': target_url,
                            'vulnerable': False,
                            'vulnerability_type': 'SSTI'
                        })
                except Exception as e:
                    results.append({
                        'parameter': param,
                        'url': target_url,
                        'vulnerable': False,
                        'error': str(e),
                        'vulnerability_type': 'SSTI'
                    })
        
        return {'tool': 'tplmap', 'results': results}
    
    def run_directory_enumeration(self, url: str) -> Dict[str, Any]:
        wordlist_path = f"{self.config.WORDLIST_DIR}/directories.txt"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        cmd = [
            'ffuf',
            '-u', f"{url}/FUZZ",
            '-w', wordlist_path,
            '-o', output_file,
            '-of', 'json',
            '-mc', '200,204,301,302,307,401,403',
            '-t', '50'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            with open(output_file, 'r') as f:
                ffuf_results = json.load(f)
            
            os.unlink(output_file)
            
            directories = []
            for item in ffuf_results.get('results', []):
                directories.append({
                    'url': item.get('url', ''),
                    'status_code': item.get('status', 0),
                    'content_length': item.get('length', 0),
                    'words': item.get('words', 0),
                    'lines': item.get('lines', 0)
                })
            
            return {'tool': 'ffuf', 'results': directories}
            
        except Exception as e:
            if os.path.exists(output_file):
                os.unlink(output_file)
            return {'tool': 'ffuf', 'error': str(e), 'results': []}
