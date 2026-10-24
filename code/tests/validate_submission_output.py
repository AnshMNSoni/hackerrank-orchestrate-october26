import csv
import json
import sys

ALLOWED_PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
ALLOWED_OPS = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

REQUIRED_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}

def validate():
    print("=== Validating root output.csv ===")
    
    # 1. Check raw file line count and header
    with open("output.csv", "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    if len(lines) != 519:
        print(f"FAIL: Line count is {len(lines)}, expected 519")
        sys.exit(1)
    
    header = lines[0].strip()
    if header != "case_id,deletion_status,steps_json":
        print(f"FAIL: Header mismatch: {header}")
        sys.exit(1)
    
    # 2. Check input case_ids
    with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
        req_cases = [r["case_id"] for r in csv.DictReader(f)]
    
    sorted_req_cases = sorted(req_cases)
    
    # 3. Parse CSV rows
    with open("output.csv", "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
    
    if len(reader) != 518:
        print(f"FAIL: Data row count is {len(reader)}, expected 518")
        sys.exit(1)
    
    out_cases = [r["case_id"] for r in reader]
    if out_cases != sorted_req_cases:
        print("FAIL: case_ids do not match sorted input cases")
        sys.exit(1)
    
    status_counts = {}
    for idx, row in enumerate(reader):
        cid = row["case_id"]
        status = row["deletion_status"]
        status_counts[status] = status_counts.get(status, 0) + 1
        
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            print(f"FAIL: Invalid status {status} at row {idx+1} ({cid})")
            sys.exit(1)
        
        try:
            steps = json.loads(row["steps_json"])
        except Exception as e:
            print(f"FAIL: Malformed JSON at row {idx+1} ({cid}): {e}")
            sys.exit(1)
            
        if not isinstance(steps, list):
            print(f"FAIL: steps_json is not an array at row {idx+1} ({cid})")
            sys.exit(1)
            
        if status == "NOT_APPLICABLE":
            if steps != []:
                print(f"FAIL: NOT_APPLICABLE must have empty array at row {idx+1} ({cid})")
                sys.exit(1)
            continue
            
        # Check phase ordering and steps
        phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        curr_phase_idx = 0
        
        for s_idx, s in enumerate(steps):
            # Consecutive numbering
            if s.get("step_no") != s_idx + 1:
                print(f"FAIL: step_no not consecutive ({s.get('step_no')} vs {s_idx+1}) at {cid}")
                sys.exit(1)
                
            # Keys check
            if set(s.keys()) != REQUIRED_KEYS:
                print(f"FAIL: Step keys mismatch at {cid} step {s_idx+1}: {set(s.keys())}")
                sys.exit(1)
                
            phase = s["phase"]
            if phase not in ALLOWED_PHASES:
                print(f"FAIL: Invalid phase {phase} at {cid} step {s_idx+1}")
                sys.exit(1)
                
            p_idx = phase_order[phase]
            if p_idx < curr_phase_idx:
                print(f"FAIL: Phase ordering violated ({phase} after earlier phase) at {cid} step {s_idx+1}")
                sys.exit(1)
            curr_phase_idx = p_idx
            
            op = s["operation"]
            if op not in ALLOWED_OPS:
                print(f"FAIL: Invalid operation {op} at {cid} step {s_idx+1}")
                sys.exit(1)
                
            expected_phase, expected_state = ALLOWED_OPS[op]
            if phase != expected_phase:
                print(f"FAIL: Operation {op} in wrong phase {phase} (expected {expected_phase}) at {cid}")
                sys.exit(1)
            if s["state"] != expected_state:
                print(f"FAIL: Operation {op} has wrong state {s['state']} (expected {expected_state}) at {cid}")
                sys.exit(1)
                
            # Evidence ID checks
            ev = s["evidence_id"]
            if status == "COMPLETE":
                if phase != "VERIFICATION":
                    print(f"FAIL: COMPLETE case has non-VERIFICATION step at {cid}")
                    sys.exit(1)
                if not ev:
                    print(f"FAIL: COMPLETE case step missing evidence_id at {cid} step {s_idx+1}")
                    sys.exit(1)
            elif status == "INCOMPLETE":
                if phase == "FINDING" and not ev:
                    print(f"FAIL: FINDING step missing evidence_id at {cid} step {s_idx+1}")
                    sys.exit(1)
                elif phase in ("REMEDIATION", "VERIFICATION") and ev != "":
                    print(f"FAIL: INCOMPLETE {phase} step must have empty evidence_id, got '{ev}' at {cid}")
                    sys.exit(1)
                    
    print(f"SUCCESS: All 518 cases validated perfectly!")
    print(f"Status distribution: {status_counts}")

if __name__ == "__main__":
    validate()
