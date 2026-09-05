import sys
from pathlib import Path
import pandas as pd
import numpy as np

# Ensure BACKEND/ is on the path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_DIR))

from ml.preprocessing import engineer_features_batch, engineer_features_single_event

def test_temporal_parity():
    # 1. Create a dummy dataset exactly as requested by user
    # 10:00 A, 10:00 B, 10:00 C, 11:00 D
    data = [
        {"event_id": "A", "username": "alice", "timestamp": "2025-08-01 10:00:00", "destination_ip": "1.1.1.1", "hour": 10, "source_country": "India"},
        {"event_id": "B", "username": "alice", "timestamp": "2025-08-01 10:00:00", "destination_ip": "2.2.2.2", "hour": 10, "source_country": "India"},
        {"event_id": "C", "username": "alice", "timestamp": "2025-08-01 10:00:00", "destination_ip": "3.3.3.3", "hour": 10, "source_country": "India"},
        {"event_id": "D", "username": "alice", "timestamp": "2025-08-01 11:00:00", "destination_ip": "4.4.4.4", "hour": 11, "source_country": "India"},
    ]
    df = pd.DataFrame(data)

    # 2. Run Batch Engineering
    df_engineered = engineer_features_batch(df.copy())
    
    # 3. Assert Strict Causality Rules (history timestamp < T)
    epus = df_engineered["events_per_user"].tolist()
    udcs = df_engineered["unique_destination_count"].tolist()
    
    print(f"Batch EPUs: {epus}")
    print(f"Batch UDCs: {udcs}")
    
    # A, B, C all happen at 10:00, so they have 0 history. count=1 (themselves)
    # D happens at 11:00, so it has 3 history events. count=4
    expected_epus = [1, 1, 1, 4]
    expected_udcs = [1, 1, 1, 4]
    
    assert epus == expected_epus, f"Batch causal events_per_user failed! Expected {expected_epus}, got {epus}"
    assert udcs == expected_udcs, f"Batch causal unique_destination_count failed! Expected {expected_udcs}, got {udcs}"
    
    print("[PASS] Batch causal temporal parity verified!")

    # 4. Check Single-Event Engineering matches Batch
    # Event D comes in live at 11:00.
    # The DB will return events A, B, C because their timestamp < 11:00.
    hist_D = [data[0], data[1], data[2]]
    ev_D_live = engineer_features_single_event(data[3], hist_D)
    
    assert ev_D_live["events_per_user"] == 4, f"Single-event EPU failed, got {ev_D_live['events_per_user']}"
    assert ev_D_live["unique_destination_count"] == 4, f"Single-event UDC failed, got {ev_D_live['unique_destination_count']}"
    
    # Event B comes in live at 10:00.
    # The DB will return NO history because query is STRICTLY < 10:00.
    hist_B = []
    ev_B_live = engineer_features_single_event(data[1], hist_B)
    
    assert ev_B_live["events_per_user"] == 1, f"Single-event EPU failed, got {ev_B_live['events_per_user']}"
    assert ev_B_live["unique_destination_count"] == 1, f"Single-event UDC failed, got {ev_B_live['unique_destination_count']}"
    
    print("[PASS] Single-event temporal parity verified!")
    print("ALL TEMPORAL TESTS PASSED")

if __name__ == "__main__":
    test_temporal_parity()
