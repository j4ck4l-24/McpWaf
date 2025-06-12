-- Initialize database with required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scan_results_target_url ON scan_results(target_url);
CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON scan_results(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_vulnerability_type ON scan_results(vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_source_analysis_target_url ON source_analysis(target_url);
CREATE INDEX IF NOT EXISTS idx_directory_enum_target_url ON directory_enum(target_url);
