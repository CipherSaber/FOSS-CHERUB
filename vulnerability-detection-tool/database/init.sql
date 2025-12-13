-- CVE Database Schema
CREATE TABLE IF NOT EXISTS cve (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    cvss_base_score DECIMAL(3,1),
    cvss_base_severity VARCHAR(10),
    cwe_ids TEXT[],
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_cve_id ON cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_cwe_ids ON cve USING GIN(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_cvss_score ON cve(cvss_base_score);

-- Insert sample CVE data
INSERT INTO cve (cve_id, description, cvss_base_score, cvss_base_severity, cwe_ids, published_date) VALUES
('CVE-2023-1234', 'SQL Injection vulnerability in web application', 9.8, 'CRITICAL', ARRAY['CWE-89'], '2023-01-15 10:00:00'),
('CVE-2023-5678', 'Command injection via user input', 9.8, 'CRITICAL', ARRAY['CWE-78'], '2023-02-20 14:30:00'),
('CVE-2023-9012', 'Cross-site scripting (XSS) vulnerability', 7.5, 'HIGH', ARRAY['CWE-79'], '2023-03-10 09:15:00'),
('CVE-2023-3456', 'Code injection through eval function', 9.8, 'CRITICAL', ARRAY['CWE-95'], '2023-04-05 16:45:00'),
('CVE-2023-7890', 'Path traversal vulnerability', 7.5, 'HIGH', ARRAY['CWE-22'], '2023-05-12 11:20:00'),
('CVE-2023-2345', 'Buffer overflow in C application', 8.1, 'HIGH', ARRAY['CWE-120'], '2023-06-08 13:10:00'),
('CVE-2023-6789', 'Insecure deserialization vulnerability', 9.8, 'CRITICAL', ARRAY['CWE-502'], '2023-07-22 08:30:00')
ON CONFLICT (cve_id) DO NOTHING;