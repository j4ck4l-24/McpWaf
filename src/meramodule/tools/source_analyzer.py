import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
import re
import json
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any

class SourceAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.chrome_options = Options()
        self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--no-sandbox')
        self.chrome_options.add_argument('--disable-dev-shm-usage')
        
    def analyze_complete_source(self, url: str) -> Dict[str, Any]:
        static_analysis = self._static_analysis(url)
        dynamic_analysis = self._dynamic_analysis(url)
        
        return {
            'static': static_analysis,
            'dynamic': dynamic_analysis,
            'combined_endpoints': self._merge_endpoints(static_analysis, dynamic_analysis)
        }
    
    def _static_analysis(self, url: str) -> Dict[str, Any]:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()  # Raise exception for bad status codes
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            analysis = {
                'js_files': self._extract_js_files(soup, url),
                'css_files': self._extract_css_files(soup, url),
                'forms': self._extract_forms(soup),
                'inputs': self._extract_inputs(soup),
                'links': self._extract_links(soup, url),
                'comments': self._extract_comments(response.text),
                'meta_tags': self._extract_meta_tags(soup),
                'api_hints': self._find_api_hints(response.text),
                'sensitive_patterns': self._find_sensitive_patterns(response.text),
                'headers': dict(response.headers)  # Include response headers
            }
            
            return analysis
            
        except Exception as e:
            return {'error': str(e), 'status_code': getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None}
    
    def _dynamic_analysis(self, url: str) -> Dict[str, Any]:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        
        # Enable performance logging
        options.set_capability('goog:loggingPrefs', {'performance': 'ALL', 'browser': 'ALL'})
        
        driver = None
        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(30)
            
            # Enable Network and Performance domains
            driver.execute_cdp_cmd('Network.enable', {})
            driver.execute_cdp_cmd('Performance.enable', {})
            
            network_requests = []
            
            def handle_request_will_be_sent(**kwargs):
                network_requests.append({
                    'url': kwargs.get('request', {}).get('url'),
                    'method': kwargs.get('request', {}).get('method'),
                    'type': kwargs.get('type')
                })
            
            # Add listener for network requests
            driver.add_cdp_listener('Network.requestWillBeSent', handle_request_will_be_sent)
            
            driver.get(url)
            
            # Wait for page load
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
            
            # Get console logs
            console_logs = driver.get_log('browser')
            
            return {
                'network_requests': network_requests,
                'console_logs': console_logs,
                'page_title': driver.title,
                'cookies': driver.get_cookies()
            }
            
        except Exception as e:
            return {'error': str(e)}
        finally:
            if driver:
                driver.quit()
    
    def _extract_js_files(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        js_files = []
        for script in soup.find_all('script'):
            if script.get('src'):
                full_url = urljoin(base_url, script['src'])
                js_content = self._fetch_js_content(full_url)
                js_files.append({
                    'url': full_url,
                    'inline': False,
                    'content_preview': js_content[:500] if js_content else '',
                    'api_endpoints': self._extract_api_from_js(js_content) if js_content else []
                })
            elif script.string:
                js_files.append({
                    'url': base_url,
                    'inline': True,
                    'content_preview': script.string[:500],
                    'api_endpoints': self._extract_api_from_js(script.string)
                })
        return js_files
    
    def _fetch_js_content(self, url: str) -> str:
        try:
            response = self.session.get(url, timeout=5)
            return response.text
        except:
            return ""
    
    def _extract_api_from_js(self, js_content: str) -> List[str]:
        api_patterns = [
            r'["\']/(api|API)/[^"\']*["\']',
            r'["\']https?://[^"\']*/(api|API)/[^"\']*["\']',
            r'fetch\(["\']([^"\']*)["\']',
            r'\.get\(["\']([^"\']*)["\']',
            r'\.post\(["\']([^"\']*)["\']',
            r'ajax\(.*url.*["\']([^"\']*)["\']',
            r'endpoint.*["\']([^"\']*)["\']'
        ]
        
        endpoints = []
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.extend(matches if isinstance(matches[0], str)  else [] for matches in [matches])
        
        return list(set(endpoints))
    
    def _extract_css_files(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        css_files = []
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                css_files.append(urljoin(base_url, link['href']))
        return css_files
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', ''),
                'inputs': []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'required': input_tag.has_attr('required')
                })
            forms.append(form_data)
        return forms
    
    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        inputs = []
        for input_tag in soup.find_all(['input', 'textarea']):
            inputs.append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'id': input_tag.get('id', ''),
                'class': input_tag.get('class', []),
                'placeholder': input_tag.get('placeholder', '')
            })
        return inputs
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []
        for link in soup.find_all('a', href=True):
            full_url = urljoin(base_url, link['href'])
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                links.append(full_url)
        return list(set(links))
    
    def _extract_comments(self, html_content: str) -> List[str]:
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, html_content, re.DOTALL)
        return [comment.strip() for comment in comments if comment.strip()]
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        meta_data = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
            content = meta.get('content')
            if name and content:
                meta_data[name] = content
        return meta_data
    
    def _find_api_hints(self, content: str) -> List[str]:
        api_patterns = [
            r'/api/v\d+/[^\s"\'<>]+',
            r'/rest/[^\s"\'<>]+',
            r'/graphql[^\s"\'<>]*',
            r'api_key',
            r'apikey',
            r'access_token',
            r'bearer',
            r'authorization'
        ]
        
        hints = []
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            hints.extend(matches)
        
        return list(set(hints))
    
    def _find_sensitive_patterns(self, content: str) -> List[Dict]:
        patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN PRIVATE KEY-----',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'password': r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'secret': r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'token': r'token["\']?\s*[:=]\s*["\'][^"\']+["\']'
        }
        
        findings = []
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': pattern_name,
                    'matches': matches,
                    'count': len(matches)
                })
        
        return findings
    
    def _merge_endpoints(self, static: Dict, dynamic: Dict) -> List[str]:
        endpoints = []
        
        if 'api_hints' in static:
            endpoints.extend(static['api_hints'])
        
        for js_file in static.get('js_files', []):
            endpoints.extend(js_file.get('api_endpoints', []))
        
        if 'ajax_endpoints' in dynamic:
            for endpoint in dynamic['ajax_endpoints']:
                endpoints.append(endpoint.get('url', ''))
        
        return list(set(filter(None, endpoints)))
    
    def _extract_loaded_scripts(self, network_requests: List[Dict]) -> List[str]:
        js_files = []
        for request in network_requests:
            if request.get('initiatorType') == 'script' or request.get('name', '').endswith('.js'):
                js_files.append(request.get('name', ''))
        return js_files
