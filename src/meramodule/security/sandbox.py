import docker
import json
import tempfile
import os
import threading
import time
from typing import Dict, Any, Optional
import subprocess
import signal

class DockerSandbox:
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception as e:
            print(f"Docker unavailable: {e}")
            self.client = None
            
        self.container_config = {
            'image': 'python:3.9-alpine',
            'network_mode': 'none',
            'mem_limit': '256m',
            'memswap_limit': '256m',
            'cpu_quota': 25000,
            'cpu_period': 100000,
            'detach': False,
            'remove': True,
            'user': 'nobody',
            'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges'],
            'read_only': True,
            'tmpfs': {'/tmp': 'rw,noexec,nosuid,size=50m'}
        }
        
    def execute_tool_safely(self, tool_name: str, args: Dict[str, Any], timeout: int = 300) -> Dict[str, Any]:
        if not self.client:
            return self._execute_without_docker(tool_name, args, timeout)
        
        try:
            command = self._build_safe_command(tool_name, args)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(args, f)
                input_file = f.name
            
            try:
                volumes = {input_file: {'bind': '/tmp/input.json', 'mode': 'ro'}}
                
                container = self.client.containers.run(
                    command=command,
                    volumes=volumes,
                    **self.container_config,
                    timeout=timeout
                )
                
                return {
                    'success': True,
                    'output': container.decode('utf-8') if isinstance(container, bytes) else str(container),
                    'tool': tool_name,
                    'sandboxed': True
                }
                
            finally:
                os.unlink(input_file)
                
        except docker.errors.ContainerError as e:
            return {
                'success': False,
                'error': f"Container error: {e.stderr.decode('utf-8') if e.stderr else str(e)}",
                'tool': tool_name,
                'sandboxed': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Sandbox error: {str(e)}",
                'tool': tool_name,
                'sandboxed': True
            }
    
    def _execute_without_docker(self, tool_name: str, args: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        print(f"Warning: Executing {tool_name} without Docker sandbox")
        
        try:
            command = self._build_host_command(tool_name, args)
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                return {
                    'success': process.returncode == 0,
                    'output': stdout,
                    'error': stderr if stderr else None,
                    'tool': tool_name,
                    'sandboxed': False,
                    'return_code': process.returncode
                }
                
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                return {
                    'success': False,
                    'error': f"Command timed out after {timeout} seconds",
                    'tool': tool_name,
                    'sandboxed': False
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f"Execution error: {str(e)}",
                'tool': tool_name,
                'sandboxed': False
            }
    
    def _build_safe_command(self, tool_name: str, args: Dict[str, Any]) -> list:
        if tool_name == 'ffuf':
            return [
                'sh', '-c',
                'apk add --no-cache ffuf && ffuf -u "$1" -w "$2" -o /tmp/output.json -of json',
                '--',
                args.get('url', ''),
                args.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            ]
        elif tool_name == 'curl':
            return [
                'curl',
                '-s', '-L', '--max-time', '10', '--max-redirs', '3',
                args.get('url', '')
            ]
        elif tool_name == 'nmap':
            return [
                'nmap',
                '-sS', '-O', '--max-retries', '1', '--host-timeout', '30s',
                args.get('target', '')
            ]
        else:
            return ['echo', f'Tool {tool_name} not supported in sandbox']
    
    def _build_host_command(self, tool_name: str, args: Dict[str, Any]) -> list:
        if tool_name == 'sqlmap':
            cmd = [
                'python3', '/usr/bin/sqlmap',
                '-u', args.get('url', ''),
                '--batch', '--level=3', '--risk=2',
                '--timeout=30', '--retries=1'
            ]
            if args.get('parameters'):
                cmd.extend(['-p', ','.join(args['parameters'])])
            return cmd
            
        elif tool_name == 'ffuf':
            return [
                'ffuf',
                '-u', args.get('url', '') + '/FUZZ',
                '-w', args.get('wordlist', '/usr/share/wordlists/dirb/common.txt'),
                '-o', '/tmp/ffuf_output.json',
                '-of', 'json',
                '-t', '10',
                '-timeout', '10'
            ]
        else:
            return ['echo', f'Tool {tool_name} execution blocked']

class ProcessLimiter:
    def __init__(self, max_processes: int = 5):
        self.max_processes = max_processes
        self.active_processes = {}
        self.lock = threading.Lock()
    
    def can_execute(self, user_id: str = "default") -> bool:
        with self.lock:
            user_processes = self.active_processes.get(user_id, 0)
            return user_processes < self.max_processes
    
    def start_process(self, user_id: str = "default") -> bool:
        with self.lock:
            if self.can_execute(user_id):
                self.active_processes[user_id] = self.active_processes.get(user_id, 0) + 1
                return True
            return False
    
    def end_process(self, user_id: str = "default"):
        with self.lock:
            if user_id in self.active_processes:
                self.active_processes[user_id] = max(0, self.active_processes[user_id] - 1)
                if self.active_processes[user_id] == 0:
                    del self.active_processes[user_id]

class NetworkIsolator:
    def __init__(self):
        self.allowed_networks = [
            '0.0.0.0/0'
        ]
        self.blocked_networks = [
            '127.0.0.0/8',
            '10.0.0.0/8', 
            '172.16.0.0/12',
            '192.168.0.0/16',
            '169.254.0.0/16',
            '::1/128',
            'fc00::/7'
        ]
    
    def is_allowed_target(self, target: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            
            for blocked in self.blocked_networks:
                if ip in ipaddress.ip_network(blocked):
                    return False
            return True
        except:
            return True

class SecurityMonitor:
    def __init__(self):
        self.suspicious_activities = []
        self.rate_limits = {}
        
    def log_activity(self, user_id: str, action: str, target: str):
        activity = {
            'user_id': user_id,
            'action': action,
            'target': target,
            'timestamp': time.time()
        }
        self.suspicious_activities.append(activity)
        
        if len(self.suspicious_activities) > 1000:
            self.suspicious_activities = self.suspicious_activities[-500:]
    
    def check_rate_limit(self, user_id: str, action: str) -> bool:
        current_time = time.time()
        key = f"{user_id}:{action}"
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        self.rate_limits[key] = [
            timestamp for timestamp in self.rate_limits[key]
            if current_time - timestamp < 3600
        ]
        
        max_requests = {
            'scan': 10,
            'recon': 5,
            'exploit': 3
        }
        
        limit = max_requests.get(action, 20)
        
        if len(self.rate_limits[key]) >= limit:
            return False
        
        self.rate_limits[key].append(current_time)
        return True
    
    def detect_suspicious_behavior(self, user_id: str) -> bool:
        recent_activities = [
            activity for activity in self.suspicious_activities
            if activity['user_id'] == user_id and 
            time.time() - activity['timestamp'] < 300
        ]
        
        if len(recent_activities) > 50:
            return True
        
        unique_targets = set(activity['target'] for activity in recent_activities)
        if len(unique_targets) > 10:
            return True
        
        return False
