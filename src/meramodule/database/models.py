from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, Float
from datetime import datetime
from .db import Base

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, index=True)
    tool_name = Column(String)
    vulnerability_type = Column(String)
    endpoint = Column(String)
    payload = Column(Text)
    response_status = Column(Integer)
    response_body = Column(Text)
    is_vulnerable = Column(Boolean, default=False)
    risk_level = Column(String)
    confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    meta_info = Column(JSON)

class SourceAnalysis(Base):
    __tablename__ = "source_analysis"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, index=True)
    js_files = Column(JSON)
    css_files = Column(JSON)
    api_endpoints = Column(JSON)
    forms = Column(JSON)
    inputs = Column(JSON)
    links = Column(JSON)
    comments = Column(JSON)
    technologies = Column(JSON)
    sensitive_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class DirectoryEnum(Base):
    __tablename__ = "directory_enum"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, index=True)
    discovered_path = Column(String)
    status_code = Column(Integer)
    content_length = Column(Integer)
    content_type = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    tool_name = Column(String)
    target = Column(String)
    command = Column(Text)
    ai_reasoning = Column(Text)
    result = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
