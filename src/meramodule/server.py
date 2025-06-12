import asyncio
import json
from fastapi import FastAPI
from mcp.server.stdio import stdio_server  # Import stdio_server
from typing import Dict, Any, List
from mcp.server import Server
from mcp.server.lowlevel import NotificationOptions  # Corrected import
from mcp.server.models import InitializationOptions  # Corrected import
from mcp.types import Tool, TextContent
from sqlalchemy.orm import Session
from .database.db import get_db, engine, Base
from .database.models import ScanResult, AuditLog, SourceAnalysis, DirectoryEnum
from .tools.recon import ComprehensiveRecon
from .tools.scanner import AdvancedScanner
from .security.validator import SecurityValidator
from .ai.orchestrator import AIOrchestrator
from .config import Config

Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/health")
async def health_check():
    return {"status": "ok"}

class MCPPentestServer:
    def __init__(self):
        self.config = Config()
        self.server = Server("mcp-waf")
        self.recon = ComprehensiveRecon()
        self.scanner = AdvancedScanner()
        self.validator = SecurityValidator()
        self.ai_orchestrator = AIOrchestrator(self)
        self._register_tools()
    
    def get_db(self):
        return get_db()
    
    def _register_tools(self):
        self.server.list_tools = self._list_tools
        self.server.call_tool = self._call_tool
    
    async def _list_tools(self) -> List[Tool]:
        return [
            Tool(
                name="ai_pentest",
                description="AI-driven intelligent penetration testing with dynamic decision making",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to test"},
                        "ai_model": {"type": "string", "description": "AI model to use", "default": "gpt-4"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="full_recon",
                description="Complete reconnaissance including source analysis, directory enumeration, and parameter discovery",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to analyze"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="vulnerability_scan",
                description="Run SQLMap, XSStrike, and TPLMap on discovered parameters",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="sqlmap_scan",
                description="SQL injection testing using SQLMap",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameters": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="xss_scan",
                description="XSS testing using XSStrike",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameters": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="ssti_scan",
                description="SSTI testing using TPLMap",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameters": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["url"]
                }
            )
        ]
    
    async def _call_tool(self, name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        
        db = next(get_db())
        
        try:
            if name == "ai_pentest":
                return await self._ai_pentest(arguments, db)
            elif name == "full_recon":
                return await self._full_recon(arguments, db)
            elif name == "vulnerability_scan":
                return await self._vulnerability_scan(arguments, db)
            elif name == "sqlmap_scan":
                return await self._sqlmap_scan(arguments, db)
            elif name == "xss_scan":
                return await self._xss_scan(arguments, db)
            elif name == "ssti_scan":
                return await self._ssti_scan(arguments, db)
            else:
                return [TextContent(type="text", text=json.dumps({"error": "Unknown tool"}))]
        finally:
            db.close()
    
    async def _ai_pentest(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        ai_model = args.get('ai_model', self.config.DEFAULT_AI_MODEL)
        
        print(f"🚀 Starting AI-driven pentest for: {url}")
        print(f"🧠 Using AI model: {ai_model}")
        
        try:
            plan = await self.ai_orchestrator.analyze_and_plan(url, ai_model)
            
            if "error" in plan:
                return [TextContent(type="text", text=json.dumps({
                    "ai_planning_error": plan["error"],
                    "fallback_used": plan.get("fallback_plan")
                }))]
            
            print(f"📋 AI Created Plan: {plan.get('strategy', 'No strategy')}")
            
            execution_results = await self.ai_orchestrator.execute_intelligent_scan(plan)
            
            audit_log = AuditLog(
                action="ai_pentest",
                tool_name="ai_orchestrator",
                target=url,
                ai_reasoning=json.dumps(plan),
                result=json.dumps(execution_results, default=str)
            )
            db.add(audit_log)
            db.commit()
            
            final_report = {
                "ai_model": ai_model,
                "target_url": url,
                "ai_plan": plan,
                "execution_results": execution_results,
                "summary": {
                    "total_steps": len(execution_results.get("step_results", [])),
                    "vulnerabilities_found": self._count_vulnerabilities(execution_results),
                    "ai_decisions_made": len(execution_results.get("ai_decisions", [])),
                    "final_assessment": execution_results.get("final_assessment", {})
                }
            }
            
            return [TextContent(type="text", text=json.dumps(final_report, indent=2, default=str))]
            
        except Exception as e:
            error_log = AuditLog(
                action="ai_pentest_error",
                tool_name="ai_orchestrator", 
                target=url,
                ai_reasoning=f"Error: {str(e)}",
                result=f"AI pentest failed: {str(e)}"
            )
            db.add(error_log)
            db.commit()
            
            return [TextContent(type="text", text=json.dumps({
                "error": f"AI pentest failed: {str(e)}",
                "fallback_suggestion": "Try using individual tools manually"
            }))]
    
    def _count_vulnerabilities(self, execution_results: Dict[str, Any]) -> int:
        vuln_count = 0
        for step_result in execution_results.get("step_results", []):
            result_text = str(step_result.get("result", ""))
            if "vulnerable" in result_text.lower() and "true" in result_text.lower():
                vuln_count += 1
        return vuln_count
    
    async def _full_recon(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        results = self.recon.full_recon(url)
        
        source_entry = SourceAnalysis(
            target_url=url,
            js_files=results['source_analysis']['static'].get('js_files', []),
            css_files=results['source_analysis']['static'].get('css_files', []),
            api_endpoints=results.get('discovered_endpoints', []),
            forms=results['source_analysis']['static'].get('forms', []),
            inputs=results['source_analysis']['static'].get('inputs', []),
            links=results['source_analysis']['static'].get('links', []),
            comments=results['source_analysis']['static'].get('comments', []),
            technologies=results['source_analysis']['static'].get('meta_tags', {}),
            sensitive_data=results['source_analysis']['static'].get('sensitive_patterns', [])
        )
        db.add(source_entry)
        
        for directory in results['directory_enumeration'].get('results', []):
            dir_entry = DirectoryEnum(
                target_url=url,
                discovered_path=directory['url'],
                status_code=directory['status_code'],
                content_length=directory['content_length'],
                content_type=""
            )
            db.add(dir_entry)
        
        db.commit()
        
        return [TextContent(type="text", text=json.dumps(results, indent=2))]
    
    async def _vulnerability_scan(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        parameters = args.get('parameters', [])
        
        sqlmap_results = self.scanner.run_sqlmap(url, parameters)
        xss_results = self.scanner.run_xsstrike(url, parameters)
        ssti_results = self.scanner.run_tplmap(url, parameters)
        
        all_results = {
            'sqlmap': sqlmap_results,
            'xsstrike': xss_results,
            'tplmap': ssti_results
        }
        
        for tool_name, tool_results in all_results.items():
            for result in tool_results.get('results', []):
                scan_entry = ScanResult(
                    target_url=url,
                    tool_name=tool_name,
                    vulnerability_type=result.get('vulnerability_type', ''),
                    endpoint=result.get('url', ''),
                    payload=result.get('parameter', ''),
                    is_vulnerable=result.get('vulnerable', False),
                    risk_level=result.get('risk_level', 'Unknown'),
                    meta_info=result
                )
                db.add(scan_entry)
        
        db.commit()
        return [TextContent(type="text", text=json.dumps(all_results, indent=2))]
    
    async def _sqlmap_scan(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        parameters = args.get('parameters', [])
        
        results = self.scanner.run_sqlmap(url, parameters)
        
        for result in results.get('results', []):
            scan_entry = ScanResult(
                target_url=url,
                tool_name='sqlmap',
                vulnerability_type='SQLi',
                endpoint=result.get('url', ''),
                payload=result.get('parameter', ''),
                is_vulnerable=result.get('vulnerable', False),
                risk_level=result.get('risk_level', 'Unknown'),
                meta_info=result
            )
            db.add(scan_entry)
        
        db.commit()
        return [TextContent(type="text", text=json.dumps(results, indent=2))]
    
    async def _xss_scan(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        parameters = args.get('parameters', [])
        
        results = self.scanner.run_xsstrike(url, parameters)
        
        for result in results.get('results', []):
            scan_entry = ScanResult(
                target_url=url,
                tool_name='xsstrike',
                vulnerability_type='XSS',
                endpoint=result.get('url', ''),
                payload=result.get('parameter', ''),
                is_vulnerable=result.get('vulnerable', False),
                risk_level=result.get('risk_level', 'Unknown'),
                meta_info=result
            )
            db.add(scan_entry)
        
        db.commit()
        return [TextContent(type="text", text=json.dumps(results, indent=2))]
    
    async def _ssti_scan(self, args: Dict[str, Any], db: Session) -> List[TextContent]:
        url = args['url']
        parameters = args.get('parameters', [])
        
        results = self.scanner.run_tplmap(url, parameters)
        
        for result in results.get('results', []):
            scan_entry = ScanResult(
                target_url=url,
                tool_name='tplmap',
                vulnerability_type='SSTI',
                endpoint=result.get('url', ''),
                payload=result.get('parameter', ''),
                is_vulnerable=result.get('vulnerable', False),
                risk_level=result.get('risk_level', 'Unknown'),
                meta_info=result
            )
            db.add(scan_entry)
        
        db.commit()
        return [TextContent(type="text", text=json.dumps(results, indent=2))]

async def main():
    server = MCPPentestServer()
    
    # Use stdio_server as a context manager to handle streams
    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="MCP-WAF",
                server_version="1.0.0",
                capabilities=server.server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
                instructions="Welcome to MCP-WAF Server",
            ),
        )

if __name__ == "__main__":
    import uvicorn
    loop = asyncio.get_event_loop()
    loop.create_task(main())
    uvicorn.run(app, host="0.0.0.0", port=8000)