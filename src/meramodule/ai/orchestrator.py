import openai
import anthropic
import json
import asyncio
from typing import Dict, Any, List, Optional
from ..config import Config
from .prompts import SYSTEM_PROMPTS, USER_PROMPTS

class AIOrchestrator:
    def __init__(self, mcp_server):
        self.config = Config()
        self.mcp_server = mcp_server
        self.openai_client = openai.OpenAI(api_key=self.config.OPENAI_API_KEY) if self.config.OPENAI_API_KEY else None
        self.anthropic_client = anthropic.Anthropic(api_key=self.config.ANTHROPIC_API_KEY) if self.config.ANTHROPIC_API_KEY else None
        self.conversation_history = []
        
    async def analyze_and_plan(self, target_url: str, ai_model: str = None) -> Dict[str, Any]:
        model = ai_model or self.config.DEFAULT_AI_MODEL
        
        prompt = USER_PROMPTS["analyze_target"](target_url)
        
        try:
            if model.startswith("gpt") and self.openai_client:
                response = await self._call_openai(
                    model=model,
                    system_prompt=SYSTEM_PROMPTS["pentest_planner"],
                    user_prompt=prompt
                )
            elif model.startswith("claude") and self.anthropic_client:
                response = await self._call_anthropic(
                    model=model,
                    system_prompt=SYSTEM_PROMPTS["pentest_planner"],
                    user_prompt=prompt
                )
            else:
                return {"error": "No AI client available or unsupported model"}
            
            plan = json.loads(response)
            plan["ai_model_used"] = model
            plan["target_url"] = target_url
            
            self.conversation_history.append({
                "role": "planning",
                "content": plan,
                "timestamp": asyncio.get_event_loop().time()
            })
            
            return plan
            
        except Exception as e:
            return {
                "error": f"AI planning failed: {str(e)}",
                "fallback_plan": self._create_fallback_plan(target_url)
            }
    
    async def execute_intelligent_scan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        target_url = plan.get("target_url")
        execution_results = {
            "plan": plan,
            "step_results": [],
            "ai_decisions": [],
            "final_assessment": {}
        }
        
        for i, step in enumerate(plan.get("steps", [])):
            print(f"\n🤖 AI Decision {i+1}: {step.get('reasoning', 'No reasoning provided')}")
            
            try:
                tool_name = step.get("tool")
                params = step.get("params", {})
                params["url"] = target_url
                
                print(f"🔧 Executing: {tool_name} with params: {params}")
                
                result = await self._execute_tool_via_mcp(tool_name, params)
                
                step_result = {
                    "step_number": i + 1,
                    "tool": tool_name,
                    "params": params,
                    "result": result,
                    "ai_reasoning": step.get("reasoning")
                }
                
                execution_results["step_results"].append(step_result)
                
                analysis = await self._analyze_step_results(result, target_url, step)
                execution_results["ai_decisions"].append(analysis)
                
                if analysis.get("stop_scanning", False):
                    print(f"🛑 AI decided to stop scanning: {analysis.get('reasoning')}")
                    break
                    
                if analysis.get("next_actions"):
                    for action in analysis["next_actions"]:
                        if action.get("tool") and action["tool"] not in [s.get("tool") for s in plan.get("steps", [])]:
                            additional_step = {
                                "tool": action["tool"],
                                "reasoning": action["reasoning"],
                                "priority": "high",
                                "params": {}
                            }
                            plan["steps"].append(additional_step)
                            print(f"🎯 AI added dynamic step: {action['tool']}")
                
            except Exception as e:
                error_result = {
                    "step_number": i + 1,
                    "tool": step.get("tool"),
                    "error": str(e),
                    "ai_reasoning": step.get("reasoning")
                }
                execution_results["step_results"].append(error_result)
                print(f"❌ Step {i+1} failed: {str(e)}")
        
        final_assessment = await self._generate_final_assessment(execution_results)
        execution_results["final_assessment"] = final_assessment
        
        return execution_results
    
    async def _execute_tool_via_mcp(self, tool_name: str, params: Dict[str, Any]) -> Any:
        db = next(self.mcp_server.get_db())
        try:
            if tool_name == "full_recon":
                return await self.mcp_server._full_recon(params, db)
            elif tool_name == "vulnerability_scan":
                return await self.mcp_server._vulnerability_scan(params, db)
            elif tool_name == "sqlmap_scan":
                return await self.mcp_server._sqlmap_scan(params, db)
            elif tool_name == "xss_scan":
                return await self.mcp_server._xss_scan(params, db)
            elif tool_name == "ssti_scan":
                return await self.mcp_server._ssti_scan(params, db)
            else:
                raise ValueError(f"Unknown tool: {tool_name}")
        finally:
            db.close()
    
    async def _analyze_step_results(self, results: Any, target_url: str, step: Dict[str, Any]) -> Dict[str, Any]:
        prompt = USER_PROMPTS["analyze_results"](str(results), target_url)
        
        try:
            response = await self._call_openai(
                model=self.config.DEFAULT_AI_MODEL,
                system_prompt=SYSTEM_PROMPTS["result_analyzer"],
                user_prompt=prompt
            )
            
            analysis = json.loads(response)
            analysis["step_context"] = step
            return analysis
            
        except Exception as e:
            return {
                "summary": "Analysis failed",
                "error": str(e),
                "next_actions": [],
                "stop_scanning": False,
                "reasoning": "Continue with default behavior due to analysis error"
            }
    
    async def _generate_final_assessment(self, execution_results: Dict[str, Any]) -> Dict[str, Any]:
        summary_prompt = f"""
Generate a comprehensive security assessment based on these penetration test results:

Execution Results: {json.dumps(execution_results, default=str, indent=2)}

Provide:
1. Executive summary
2. Critical vulnerabilities found
3. Risk score (1-10)
4. Immediate actions required
5. Long-term security recommendations
        """
        
        try:
            response = await self._call_openai(
                model=self.config.DEFAULT_AI_MODEL,
                system_prompt=SYSTEM_PROMPTS["report_generator"],
                user_prompt=summary_prompt
            )
            
            return {
                "report": response,
                "generated_at": asyncio.get_event_loop().time(),
                "ai_model": self.config.DEFAULT_AI_MODEL
            }
            
        except Exception as e:
            return {
                "error": f"Report generation failed: {str(e)}",
                "basic_summary": self._create_basic_summary(execution_results)
            }
    
    async def _call_openai(self, model: str, system_prompt: str, user_prompt: str) -> str:
        if not self.openai_client:
            raise ValueError("OpenAI client not configured")
            
        response = await self.openai_client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1
        )
        
        return response.choices[0].message.content
    
    async def _call_anthropic(self, model: str, system_prompt: str, user_prompt: str) -> str:
        if not self.anthropic_client:
            raise ValueError("Anthropic client not configured")
            
        response = await self.anthropic_client.messages.create(
            model=model,
            max_tokens=4000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        return response.content[0].text
    
    def _create_fallback_plan(self, target_url: str) -> Dict[str, Any]:
        return {
            "analysis": "Fallback plan - AI unavailable",
            "strategy": "Standard web application penetration test sequence",
            "steps": [
                {
                    "tool": "full_recon",
                    "reasoning": "Always start with reconnaissance",
                    "priority": "high",
                    "params": {}
                },
                {
                    "tool": "vulnerability_scan",
                    "reasoning": "Test for common vulnerabilities",
                    "priority": "high", 
                    "params": {}
                }
            ],
            "risk_areas": ["SQLi", "XSS", "SSTI"],
            "expected_findings": ["Standard web vulnerabilities"]
        }
    
    def _create_basic_summary(self, execution_results: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities_found = 0
        critical_issues = 0
        
        for step_result in execution_results.get("step_results", []):
            if "vulnerable" in str(step_result.get("result", "")):
                vulnerabilities_found += 1
            if "critical" in str(step_result.get("result", "")).lower():
                critical_issues += 1
        
        return {
            "total_vulnerabilities": vulnerabilities_found,
            "critical_issues": critical_issues,
            "scan_completed": True,
            "recommendation": "Review findings and prioritize remediation"
        }
