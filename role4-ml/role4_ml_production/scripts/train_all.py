from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.preprocessing import label_binarize
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from role4_ml.features import dns_feature_vector, encrypted_feature_vector, sequence_matrix
from role4_ml.sequence_model import train_sequence_model

random.seed(42)
np.random.seed(42)
DATA = ROOT / "data"
MODELS = ROOT / "models"
DATA.mkdir(exist_ok=True)
MODELS.mkdir(exist_ok=True)


def random_domain(kind: str) -> str:
    benign = ["google.com", "microsoft.com", "github.com", "cloudflare.com", "openai.com", "wikipedia.org", "amazon.com"]
    if kind == "BENIGN_DNS":
        return random.choice(benign)
    if kind == "DGA":
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(random.choice(alphabet) for _ in range(random.randint(16, 26))) + ".com"
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(random.randint(35, 60))) + ".tunnel.example"


def dns_dataset(n_each=400):
    rows=[]
    for label in ["BENIGN_DNS","DGA","DNS_TUNNELING"]:
        for _ in range(n_each):
            domain=random_domain(label)
            f=dns_feature_vector(domain)
            f["dns_record_type"] = random.choice(["A","AAAA","TXT","CNAME"]) if label != "BENIGN_DNS" else "A"
            f["label"]=label
            rows.append(f)
    return pd.DataFrame(rows)


def encrypted_sequence(label: str):
    count=random.randint(18, 48)
    if label=="BOTNET_C2":
        interval=random.uniform(0.8, 1.5)
        ts=np.cumsum(np.random.normal(interval, interval*0.04, count)).tolist()
        sizes=np.random.choice([110,120,130,140,900,950], size=count, p=[.18,.18,.12,.12,.2,.2]).tolist()
    elif label=="ENCRYPTED_MALWARE":
        iats=np.random.lognormal(mean=-0.2, sigma=0.8, size=count)
        ts=np.cumsum(iats).tolist()
        sizes=np.random.randint(60,1400,size=count).tolist()
    else:
        iats=np.random.lognormal(mean=-0.1, sigma=1.1, size=count)
        ts=np.cumsum(iats).tolist()
        sizes=np.random.randint(60,1500,size=count).tolist()
    sizes=[int(x) if i%2==0 else -int(x) for i,x in enumerate(sizes)]
    return sizes, ts


def encrypted_dataset(n_each=500):
    rows=[]
    sequences=[]
    labels=[]
    for label in ["BENIGN_ENCRYPTED","ENCRYPTED_MALWARE","BOTNET_C2"]:
        for _ in range(n_each):
            sizes,ts=encrypted_sequence(label)
            ja3="UNKNOWN" if label=="BENIGN_ENCRYPTED" else random.choice(["ja3_demo","ja3_alt","ja3_seen"])
            ja4="UNKNOWN" if label=="BENIGN_ENCRYPTED" else random.choice(["ja4_demo","ja4_alt","ja4_seen"])
            tls=random.choice(["TLS1.2","TLS1.3"])
            f=encrypted_feature_vector(sizes,ts,ja3,ja4,tls,False)
            f["label"]=label
            rows.append(f)
            sequences.append(sequence_matrix(sizes,ts))
            labels.append(["BENIGN_ENCRYPTED","ENCRYPTED_MALWARE","BOTNET_C2"].index(label))
    return pd.DataFrame(rows), np.stack(sequences), np.array(labels,dtype=np.int64)


def train_catboost(df: pd.DataFrame, label_col: str, output_name: str):
    X=df.drop(columns=[label_col]).copy()
    y=df[label_col]
    categorical=[]
    for c in X.columns:
        if X[c].dtype=="object" or str(X[c].dtype).startswith("string"):
            categorical.append(c)
            X[c]=X[c].fillna("UNKNOWN").astype(str)
        else:
            X[c]=pd.to_numeric(X[c],errors="coerce").fillna(0.0)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    model=CatBoostClassifier(iterations=350,depth=7,learning_rate=.06,loss_function="MultiClass",verbose=False,random_seed=42)
    model.fit(Xtr,ytr,cat_features=categorical,eval_set=(Xte,yte))
    pred=model.predict(Xte).flatten()
    probs=model.predict_proba(Xte)
    classes=[str(x) for x in model.classes_]
    y_bin=label_binarize(yte, classes=classes)
    if len(classes)==2:
        pr_auc=float(average_precision_score(y_bin, probs[:,1]))
    else:
        pr_auc=float(average_precision_score(y_bin, probs, average="macro"))
    precision, recall, f1, _=precision_recall_fscore_support(yte,pred,average="macro",zero_division=0)
    print(f"\n{output_name} accuracy: {accuracy_score(yte,pred):.4f}")
    print(classification_report(yte,pred,zero_division=0))
    model.save_model(str(MODELS/output_name))
    with open(MODELS/(output_name.replace('.cbm','_metadata.json')),'w',encoding='utf-8') as f:
        json.dump({"features":list(X.columns),"categorical_features":categorical,"classes":classes,"metrics":{"accuracy":float(accuracy_score(yte,pred)),"precision_macro":float(precision),"recall_macro":float(recall),"f1_macro":float(f1),"pr_auc_macro":pr_auc}},f,indent=2)


def main():
    dns=dns_dataset()
    dns.to_csv(DATA/'dns_training_demo.csv',index=False)
    train_catboost(dns,"label","dns_catboost.cbm")

    enc, Xseq, yseq=encrypted_dataset()
    enc.to_csv(DATA/'encrypted_training_demo.csv',index=False)
    train_catboost(enc,"label","encrypted_catboost.cbm")
    train_sequence_model(Xseq,yseq,str(MODELS/'role4_sequence_lstm.pt'),classes=3,epochs=20)

    def percentiles(frame, cols):
        result={}
        benign=frame[frame['label'].isin(['BENIGN_DNS','BENIGN_ENCRYPTED'])]
        for col in cols:
            if col in benign.columns:
                vals=pd.to_numeric(benign[col],errors='coerce').dropna()
                if len(vals):
                    result[col]={"p05":float(vals.quantile(.05)),"p50":float(vals.quantile(.50)),"p95":float(vals.quantile(.95)),"mean":float(vals.mean()),"std":float(vals.std(ddof=0))}
        return result
    baseline={"dns":percentiles(dns,['dns_entropy','dns_query_length','dns_ngram3_unique_ratio']),"encrypted":percentiles(enc,['periodicity_score','iat_cv','packet_size_mean'])}
    with open(MODELS/'baseline_profile.json','w',encoding='utf-8') as f:
        json.dump(baseline,f,indent=2)

    # Combined manifest for reproducibility.
    with open(MODELS/'model_manifest.json','w',encoding='utf-8') as f:
        json.dump({
            "version":"role4-2.0.0-demo",
            "dns_model":"dns_catboost.cbm",
            "encrypted_model":"encrypted_catboost.cbm",
            "sequence_model":"role4_sequence_lstm.pt",
            "classes":{
                "dns":["BENIGN_DNS","DGA","DNS_TUNNELING"],
                "encrypted":["BENIGN_ENCRYPTED","ENCRYPTED_MALWARE","BOTNET_C2"]
            },
            "note":"Models are demonstration models trained on generated synthetic data. Replace with validated labeled telemetry before production claims."
        },f,indent=2)
    print("\nTraining complete. Models written to", MODELS)

if __name__=='__main__':
    main()
