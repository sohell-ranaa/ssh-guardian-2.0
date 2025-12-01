import json
import pandas as pd
from pathlib import Path
from datetime import datetime

def compare_all_models():
    """Compare all trained model results"""
    
    results_dir = Path("src/ml/results")
    result_files = list(results_dir.glob("*.json"))
    
    if not result_files:
        print("❌ No model results found!")
        return
    
    print("🔍 TRAINED MODELS COMPARISON")
    print("="*80)
    
    comparison_data = []
    
    for result_file in result_files:
        with open(result_file, 'r') as f:
            data = json.load(f)
        
        metrics = data['performance_metrics']
        comparison_data.append({
            'Model': data['model_type'],
            'Timestamp': data['timestamp'],
            'Accuracy': f"{metrics['accuracy']*100:.1f}%",
            'Precision': f"{metrics['precision']*100:.1f}%",
            'Recall': f"{metrics['recall']*100:.1f}%",
            'F1-Score': f"{metrics['f1_score']*100:.1f}%",
            'Train_Size': metrics['train_size'],
            'Test_Size': metrics['test_size']
        })
    
    # Create comparison table
    df = pd.DataFrame(comparison_data)
    print(df.to_string(index=False))
    
    # Find best model
    best_f1_idx = df['F1-Score'].str.rstrip('%').astype(float).idxmax()
    best_model = df.iloc[best_f1_idx]
    
    print(f"\n🏆 BEST MODEL (by F1-Score):")
    print(f"   {best_model['Model']} - {best_model['Timestamp']}")
    print(f"   F1-Score: {best_model['F1-Score']}")

if __name__ == "__main__":
    compare_all_models()