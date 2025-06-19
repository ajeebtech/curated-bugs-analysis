import json
with open("smartbugs-curated/vulnerabilities.json", "r") as f:
    ground_truth_data = json.load(f)

from pathlib import Path
from collections import defaultdict

def load_gemini_predictions(results_dir="analysis_results"):
    predictions = defaultdict(list)
    
    for category_dir in Path(results_dir).iterdir():
        for result_file in category_dir.glob("*_analysis.json"):
            with open(result_file, 'r') as f:
                result = json.load(f)

            if result["status"] == "success":
                rel_path = str(result_file).replace("analysis_results/", "").replace("_analysis.json", ".sol")
                predictions[rel_path] = result["vulnerabilities"]
    
    return predictions


def match_vulns(gt, pred):
    gt_set = {(line, cat) for v in gt for line in v['lines'] for cat in [v['category']]}
    pred_set = {(v['line'], v['category']) for v in pred}
    return gt_set, pred_set

def evaluate_all(ground_truth_data, gemini_predictions):
    tp, fp, fn = 0, 0, 0
    
    for item in ground_truth_data:
        rel_path = item['path'].replace("smartbugs-curated/dataset/", "")
        gt_set, pred_set = match_vulns(item['vulnerabilities'], gemini_predictions.get(rel_path, []))
        
        tp += len(gt_set & pred_set)
        fp += len(pred_set - gt_set)
        fn += len(gt_set - pred_set)

        # Print per-contract (optional)
        if gt_set or pred_set:
            print(f"\n📄 {rel_path}")
            print(f"✅ TP: {gt_set & pred_set}")
            print(f"❌ FP: {pred_set - gt_set}")
            print(f"🛑 FN: {gt_set - pred_set}")
    
    # Metrics
    precision = tp / (tp + fp + 1e-6)
    recall = tp / (tp + fn + 1e-6)
    f1 = 2 * precision * recall / (precision + recall + 1e-6)

    print("\n🧠 Gemini Performance:")
    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1 Score:  {f1:.2f}")

ground_truth_data = json.load(open("smartbugs-curated/vulnerabilities.json"))
gemini_predictions = load_gemini_predictions("analysis_results")
evaluate_all(ground_truth_data, gemini_predictions)