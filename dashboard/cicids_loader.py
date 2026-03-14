"""
dashboard/cicids_loader.py
---------------------------
CIC-IDS 2017 dataset loader for the CyberWatch dashboard.

The CIC-IDS dataset contains network flow features but lacks:
- Timestamps (only flow durations)
- Source/Destination IP addresses (anonymized)

This loader:
1. Reads the CSV with robust encoding handling
2. Generates synthetic timestamps based on flow order
3. Creates synthetic IP addresses based on flow patterns
4. Maps the Label column to attack_type
5. Derives severity from attack type
"""

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta, timezone
import random


def load_cicids_csv(csv_path: Path, max_rows: int = None) -> pd.DataFrame:
    """
    Load CIC-IDS CSV and transform it into dashboard-compatible format.
    
    Args:
        csv_path: Path to CIC-IDS CSV file
        max_rows: Optional limit on rows to load (for testing)
    
    Returns:
        DataFrame with columns: timestamp, ip, attack_type, confidence, 
                                url, status_code, rules, level
    """
    
    # Step 1: Load CSV with encoding fallback
    df = None
    for encoding in ['utf-8', 'latin-1', 'cp1252']:
        try:
            df = pd.read_csv(csv_path, encoding=encoding, nrows=max_rows)
            print(f"[CICIDSLoader] Loaded {len(df)} rows with encoding: {encoding}")
            break
        except UnicodeDecodeError:
            continue
    
    if df is None:
        raise ValueError(f"Could not load {csv_path} with any encoding")
    
    # Step 2: Clean column names (remove leading spaces)
    df.columns = df.columns.str.strip()
    
    # Step 3: Check for required Label column
    if 'Label' not in df.columns:
        raise ValueError(f"Required 'Label' column not found. Available: {list(df.columns)}")
    
    # Step 4: Generate synthetic timestamps
    # Spread flows over the last 24 hours, with attacks clustered
    base_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    
    timestamps = []
    for i, label in enumerate(df['Label']):
        if label != 'BENIGN':
            # Attacks clustered in recent hours (last 6 hours)
            offset_hours = random.uniform(18, 24)
        else:
            # Normal traffic spread throughout
            offset_hours = random.uniform(0, 24)
        
        ts = base_time + timedelta(hours=offset_hours, seconds=random.uniform(0, 3600))
        timestamps.append(ts)
    
    df['timestamp'] = timestamps
    
    # Step 5: Generate synthetic IP addresses
    # Use flow features to create consistent IPs
    np.random.seed(42)
    
    # For attacks: use a smaller pool of "attacker" IPs
    # For benign: use a larger pool of "normal" IPs
    attacker_ips = [f"203.0.113.{i}" for i in range(1, 20)]  # Suspicious range
    normal_ips = [f"10.0.{i}.{j}" for i in range(0, 5) for j in range(1, 50)]
    
    ips = []
    for label in df['Label']:
        if label != 'BENIGN':
            ips.append(random.choice(attacker_ips))
        else:
            ips.append(random.choice(normal_ips))
    
    df['ip'] = ips
    
    # Step 6: Map Label to attack_type
    df['attack_type'] = df['Label'].apply(lambda x: x.lower().replace(' ', '_') if x != 'BENIGN' else 'unknown')
    
    # Step 7: Generate confidence scores based on flow features
    # Use a combination of packet counts and flow duration as a proxy
    if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
        total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
        # Normalize to 0-1 range, attacks get higher confidence
        df['confidence'] = np.where(
            df['Label'] != 'BENIGN',
            np.clip(0.65 + (total_packets / total_packets.max()) * 0.30, 0.65, 0.99),
            np.clip(0.30 + (total_packets / total_packets.max()) * 0.30, 0.30, 0.65)
        )
    else:
        # Fallback: random confidence
        df['confidence'] = np.where(
            df['Label'] != 'BENIGN',
            np.random.uniform(0.65, 0.95, len(df)),
            np.random.uniform(0.30, 0.60, len(df))
        )
    
    # Step 8: Generate synthetic URLs based on attack type
    url_map = {
        'portscan': ['/admin', '/login', '/api/status', '/phpmyadmin'],
        'ddos': ['/index.html', '/', '/api/data'],
        'web_attack': ['/wp-login.php', '/admin', '/phpmyadmin'],
        'brute_force': ['/login', '/admin/login'],
        'sql_injection': ['/search', '/api/query', '/products'],
        'unknown': ['/index.html', '/about', '/api/data']
    }
    
    df['url'] = df['attack_type'].apply(lambda x: random.choice(url_map.get(x, url_map['unknown'])))
    
    # Step 9: Generate status codes
    df['status_code'] = np.where(
        df['Label'] != 'BENIGN',
        np.random.choice([401, 403, 404, 500], len(df)),
        np.random.choice([200, 200, 200, 304], len(df))  # Mostly 200 for benign
    )
    
    # Step 10: Generate rules based on attack patterns
    rules_map = {
        'portscan': 'port_scan,suspicious_agent',
        'ddos': 'high_request_rate,ddos_pattern',
        'web_attack': 'suspicious_agent,web_exploit',
        'brute_force': 'brute_force,high_error_rate',
        'sql_injection': 'sql_pattern,suspicious_input',
        'unknown': ''
    }
    
    df['rules'] = df['attack_type'].apply(lambda x: rules_map.get(x, ''))
    
    # Step 11: Assign threat level (ALERT vs WATCH)
    # Attacks with high confidence → ALERT, lower → WATCH
    df['level'] = np.where(
        (df['Label'] != 'BENIGN') & (df['confidence'] >= 0.75),
        'ALERT',
        np.where(df['Label'] != 'BENIGN', 'WATCH', None)
    )
    
    # Step 12: Filter to only threats (drop BENIGN with no level)
    df_threats = df[df['level'].notna()].copy()
    
    # Step 13: Select final columns for dashboard
    final_cols = ['timestamp', 'level', 'ip', 'attack_type', 'confidence', 
                  'url', 'status_code', 'rules']
    
    df_final = df_threats[final_cols].copy()
    
    print(f"[CICIDSLoader] Processed {len(df_final)} threats from {len(df)} total flows")
    print(f"[CICIDSLoader] Attack distribution:")
    print(df_final['attack_type'].value_counts())
    print(f"[CICIDSLoader] Level distribution: {df_final['level'].value_counts().to_dict()}")
    
    return df_final


def load_cicids_for_dashboard(csv_path: str = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv") -> pd.DataFrame:
    """
    Convenience function for dashboard integration.
    
    Returns a DataFrame ready for the CyberWatch dashboard.
    """
    path = Path(csv_path)
    
    if not path.exists():
        raise FileNotFoundError(f"CIC-IDS CSV not found at {csv_path}")
    
    return load_cicids_csv(path)



if __name__ == "__main__":
    # Test the loader
    print("Testing CIC-IDS loader...\n")
    df = load_cicids_for_dashboard()
    
    print(f"\n=== LOADER TEST RESULTS ===")
    print(f"Total rows: {len(df)}")
    print(f"Columns: {list(df.columns)}")
    print(f"\nFirst 3 rows:")
    print(df.head(3).to_string())
    print(f"\nTimestamp range:")
    print(f"  Min: {df['timestamp'].min()}")
    print(f"  Max: {df['timestamp'].max()}")
    print(f"\nData types:")
    print(df.dtypes)
