import requests
from .source_analyzer import SourceAnalyzer
from .scanner import AdvancedScanner
from typing import Dict, Any, List

class ComprehensiveRecon:
    def __init__(self):
        self.source_analyzer = SourceAnalyzer()
        self.scanner = AdvancedScanner()
        self.session = requests.Session()
    
    def full_recon(self, url: str) -> Dict[str, Any]:
        print(f"Starting comprehensive reconnaissance for: {url}")
        
        source_analysis = self.source_analyzer.analyze_complete_source(url)
        directory_enum = self.scanner.run_directory_enumeration(url)
        
        discovered_parameters = self._extract_parameters_from_analysis(source_analysis)
        
        return {
            'target_url': url,
            'source_analysis': source_analysis,
            'directory_enumeration': directory_enum,
            'discovered_parameters': discovered_parameters,
            'discovered_endpoints': source_analysis.get('combined_endpoints', [])
        }
    
    def _extract_parameters_from_analysis(self, analysis: Dict[str, Any]) -> List[str]:
        parameters = []
        
        static_data = analysis.get('static', {})
        
        for form in static_data.get('forms', []):
            for input_field in form.get('inputs', []):
                param_name = input_field.get('name', '')
                if param_name:
                    parameters.append(param_name)
        
        for input_field in static_data.get('inputs', []):
            param_name = input_field.get('name', '')
            if param_name:
                parameters.append(param_name)
        
        return list(set(filter(None, parameters)))
