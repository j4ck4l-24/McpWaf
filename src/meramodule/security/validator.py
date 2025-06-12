import re
from typing import Dict, Any, List
from urllib.parse import urlparse
import ipaddress

class SecurityValidator:
    def __init__(self: List[str]):
        self.blocked_commands = [
            'rm -rf', 'shutdown', 'reboot', 'format', 'del /f', 'rmdir /s', 
            'powershell', 'cmd.exe', 'bash', '/bin/sh', 'nc -e', 'netcat',
            'curl -X POST', 'wget -O', 'python -c', 'eval', 'exec',
            'import os', 'subprocess', '__import__', 'open('
        ]
        self.blocked_domains = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'internal', 'private', 'admin', 'root'
        ]
        self.allowed_ports = [80, 443, 8080, 8443, 3000, 5000]
        
    def validate_target(self, url: str) -> bool:
        try:
            parsed_url = urlparse(url)
            
            if not parsed_url.scheme or not parsed_url.netloc:
                return False
            
            if parsed_url.scheme not in ['http', 'https']:
                return False
            
            if self._is_private_ip(parsed_url.hostname):
                return False
                
            if self._is_blocked_domain(parsed_url.hostname):
                return False
            
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            return True
            
        except Exception:
            return False
    
    def validate_command(self, command: str) -> bool:
        command_lower = command.lower()
        return not any(blocked in command_lower for blocked in self.blocked_commands)
    
    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for key, value in params.items():
            if isinstance(value, str):
                sanitized[key] = self._sanitize_string(value)
            elif isinstance(value, list):
                sanitized[key] = [self._sanitize_string(str(item)) for item in value]
            else:
                sanitized[key] = value
        return sanitized
    
    def validate_payload(self, payload: str) -> bool:
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'file://',
            r'\\\\',
            r'\.\./|\.\.\\',
            r'union\s+select',
            r'drop\s+table',
            r'delete\s+from',
            r'insert\s+into',
            r'update\s+.*\s+set',
            r'exec\(',
            r'system\(',
            r'passthru\(',
            r'shell_exec\(',
            r'eval\(',
            r'base64_decode\(',
        ]
        
        payload_lower = payload.lower()
        return not any(re.search(pattern, payload_lower, re.IGNORECASE) for pattern in dangerous_patterns)
    
    def _is_private_ip(self, hostname: str) -> bool:
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return False
    
    def _is_blocked_domain(self, hostname: str) -> bool:
        if not hostname:
            return True
        return any(blocked in hostname.lower() for blocked in self.blocked_domains)
    
    def _sanitize_string(self, value: str) -> str:
        value = re.sub(r'[<>"\']', '', value)
        value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        return value[:1000]
    
    def check_rate_limit(self, target: str, current_requests: int) -> bool:
        return current_requests < 1000
    
    def validate_file_upload(self, filename: str, content: bytes) -> bool:
        allowed_extensions = ['.txt', '.json', '.xml', '.html']
        dangerous_extensions = ['.exe', '.bat', '.sh', '.py', '.php', '.jsp']
        
        file_ext = '.' + filename.split('.')[-1].lower()
        
        if file_ext in dangerous_extensions:
            return False
        
        if len(content) > 10 * 1024 * 1024:
            return False
        
        return True
