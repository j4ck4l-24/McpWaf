import os
from dataclasses import dataclass
from typing import List

@dataclass
class Config:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/mcpwaf")
    MAX_REQUESTS_PER_TARGET: int = 1000
    SANDBOX_ENABLED: bool = True
    WORDLIST_DIR: str = "wordlists"
    SQLMAP_PATH: str = "/usr/bin/sqlmap"
    XSSTRIKE_PATH: str = "/opt/XSStrike/xsstrike.py"
    TPLMAP_PATH: str = "/opt/tplmap/tplmap.py"
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    DEFAULT_AI_MODEL: str = "gpt-4"
