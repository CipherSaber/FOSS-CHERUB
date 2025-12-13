#!/usr/bin/env python3
"""
NVD API CVE Data Synchronization Script
Fetches CVE data from NVD API and populates PostgreSQL database
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import time
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDSync:
    def __init__(self, api_key: str, db_config: dict):
        self.api_key = api_key
        self.db_config = db_config
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        return psycopg2.connect(**self.db_config)
    
    def fetch_cves(self, start_date: str = None, results_per_page: int = 100):
        """Fetch CVEs from NVD API"""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": 0
        }
        
        if start_date:
            params["pubStartDate"] = start_date
            
        all_cves = []
        
        while True:
            try:
                response = requests.get(self.base_url, headers=headers, params=params)
                response.raise_for_status()
                
                data = response.json()
                cves = data.get("vulnerabilities", [])
                
                if not cves:
                    break
                    
                all_cves.extend(cves)
                logger.info(f"Fetched {len(cves)} CVEs (total: {len(all_cves)})")
                
                # Check if we have more results
                total_results = data.get("totalResults", 0)
                if params["startIndex"] + results_per_page >= total_results:
                    break
                    
                params["startIndex"] += results_per_page
                
                # Rate limiting - NVD allows 5 requests per 30 seconds without API key
                time.sleep(6 if not self.api_key else 0.6)
                
            except Exception as e:
                logger.error(f"Error fetching CVEs: {e}")
                break
                
        return all_cves
    
    def extract_cwe_ids(self, cve_data):
        """Extract CWE IDs from CVE data"""
        cwe_ids = []
        
        try:
            weaknesses = cve_data.get("cve", {}).get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_ids.append(cwe_id)
        except Exception:
            pass
            
        return cwe_ids
    
    def insert_cve(self, conn, cve_data):
        """Insert CVE into database"""
        try:
            cve = cve_data.get("cve", {})
            cve_id = cve.get("id", "")
            
            if not cve_id:
                return False
                
            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS data
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_severity = None
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity", "").upper()
                    break
            
            # Extract CWE IDs
            cwe_ids = self.extract_cwe_ids(cve_data)
            
            # Extract dates
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")
            
            # Convert to datetime
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
            mod_date = datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None
            
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cve (cve_id, description, cvss_base_score, cvss_base_severity, 
                                   cwe_ids, published_date, last_modified)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        cvss_base_score = EXCLUDED.cvss_base_score,
                        cvss_base_severity = EXCLUDED.cvss_base_severity,
                        cwe_ids = EXCLUDED.cwe_ids,
                        last_modified = EXCLUDED.last_modified
                """, (cve_id, description, cvss_score, cvss_severity, cwe_ids, pub_date, mod_date))
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting CVE {cve_id}: {e}")
            return False
    
    def sync_recent_cves(self, days_back: int = 30):
        """Sync CVEs from the last N days"""
        start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
        
        logger.info(f"Syncing CVEs from {start_date}")
        
        cves = self.fetch_cves(start_date=start_date)
        
        if not cves:
            logger.info("No CVEs to sync")
            return
            
        conn = self.connect_db()
        inserted = 0
        
        try:
            for cve_data in cves:
                if self.insert_cve(conn, cve_data):
                    inserted += 1
                    
            conn.commit()
            logger.info(f"Successfully synced {inserted} CVEs")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error during sync: {e}")
        finally:
            conn.close()

def main():
    # Database configuration
    db_config = {
        "host": "localhost",
        "port": 5432,
        "database": "foss_cherub",
        "user": "postgres",
        "password": "foss_cherub_2024"
    }
    
    # Get API key from environment variable
    api_key = os.getenv("NVD_API_KEY")
    
    if not api_key:
        logger.warning("No NVD_API_KEY provided. Using public API (rate limited)")
    
    syncer = NVDSync(api_key, db_config)
    
    # Try to connect to database, if fails, just test API
    try:
        syncer.sync_recent_cves(days_back=7)  # Reduced to 7 days
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        logger.info("Testing NVD API connection...")
        cves = syncer.fetch_cves(results_per_page=5)
        logger.info(f"Successfully fetched {len(cves)} CVEs from NVD API")

if __name__ == "__main__":
    main()