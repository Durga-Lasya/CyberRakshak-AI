import csv
from pathlib import Path
from .detector import analyze_transcript

DATA=Path(__file__).resolve().parent.parent/"data"/"evaluation_samples.csv"

def load_dataset():
    with DATA.open(encoding="utf-8",newline="") as f:
        return list(csv.DictReader(f))

def evaluate_dataset(rows):
    tp=fp=tn=fn=0
    for row in rows:
        actual=int(row["label"])
        predicted=int(analyze_transcript(row["transcript"])["score"]>=50)
        if actual and predicted: tp+=1
        elif not actual and predicted: fp+=1
        elif not actual and not predicted: tn+=1
        else: fn+=1
    precision=tp/(tp+fp) if tp+fp else 0
    recall=tp/(tp+fn) if tp+fn else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    accuracy=(tp+tn)/(tp+tn+fp+fn) if tp+tn+fp+fn else 0
    return {"count":len(rows),"tp":tp,"fp":fp,"tn":tn,"fn":fn,"precision":precision,"recall":recall,"f1":f1,"accuracy":accuracy,
            "confusion_matrix":[[tn,fp],[fn,tp]]}
