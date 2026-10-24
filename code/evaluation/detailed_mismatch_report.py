import csv
import json
import os
from collections import defaultdict

def run_report():
    pred_path = 'sample_pred.csv'
    truth_path = 'dataset/sample_output.csv'
    
    with open(pred_path, encoding='utf-8') as f:
        pred_rows = {r['case_id']: r for r in csv.DictReader(f)}
    with open(truth_path, encoding='utf-8') as f:
        truth_rows = {r['case_id']: r for r in csv.DictReader(f)}
        
    categories = defaultdict(list)
    
    for cid, tr in sorted(truth_rows.items()):
        pr = pred_rows.get(cid)
        t_status = tr['deletion_status']
        p_status = pr['deletion_status'] if pr else 'MISSING'
        t_steps = json.loads(tr['steps_json'])
        p_steps = json.loads(pr['steps_json']) if pr else []
        
        is_exact = (t_status == p_status and t_steps == p_steps)
        if is_exact:
            continue
            
        print(f"\n==================================================")
        print(f"CASE: {cid} | Status: Pred={p_status} | Truth={t_status}")
        print(f"Steps count: Pred={len(p_steps)} | Truth={len(t_steps)}")
        
        # Compare steps
        t_tuples = [(s.get('phase'), s.get('system_id'), s.get('resource_id'), s.get('operation'), s.get('state'), s.get('evidence_id')) for s in t_steps]
        p_tuples = [(s.get('phase'), s.get('system_id'), s.get('resource_id'), s.get('operation'), s.get('state'), s.get('evidence_id')) for s in p_steps]
        
        missing = [s for s, tup in zip(t_steps, t_tuples) if tup not in p_tuples]
        extra = [s for s, tup in zip(p_steps, p_tuples) if tup not in t_tuples]
        
        if missing:
            print("  Missing steps:")
            for m in missing:
                print(f"    - #{m.get('step_no')} {m.get('phase')} {m.get('system_id')}:{m.get('resource_id')} {m.get('operation')} {m.get('state')} ev={m.get('evidence_id')}")
        if extra:
            print("  Extra steps:")
            for e in extra:
                print(f"    + #{e.get('step_no')} {e.get('phase')} {e.get('system_id')}:{e.get('resource_id')} {e.get('operation')} {e.get('state')} ev={e.get('evidence_id')}")

if __name__ == '__main__':
    run_report()
