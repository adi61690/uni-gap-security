from __future__ import annotations
from pathlib import Path
import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE=True
except Exception:
    torch=None; nn=None; TORCH_AVAILABLE=False

if TORCH_AVAILABLE:
    class BeaconLSTM(nn.Module):
        def __init__(self, hidden=24):
            super().__init__()
            self.lstm=nn.LSTM(input_size=1,hidden_size=hidden,batch_first=True)
            self.head=nn.Sequential(nn.Linear(hidden,16),nn.ReLU(),nn.Linear(16,1))
        def forward(self,x):
            y,_=self.lstm(x)
            return self.head(y[:,-1,:]).squeeze(-1)
else:
    BeaconLSTM=object

def train_lstm(model_path='models/role3_beacon_lstm.pt', seed=42):
    if not TORCH_AVAILABLE:
        return {'trained':False,'reason':'PyTorch not installed'}
    torch.manual_seed(seed); np.random.seed(seed)
    n=240; seq=32
    benign=np.random.lognormal(mean=-2.3,sigma=.55,size=(n//2,seq)).astype('float32')
    phase=np.linspace(0,2*np.pi,seq)
    beacon=(0.18+0.02*np.sin(phase)).astype('float32')
    periodic=np.stack([beacon+np.random.normal(0,.008,seq) for _ in range(n//2)]).astype('float32')
    X=np.concatenate([benign,periodic],axis=0)[:,:,None]
    y=np.concatenate([np.zeros(n//2),np.ones(n//2)]).astype('float32')
    order=np.random.permutation(n); X=torch.tensor(X[order]); y=torch.tensor(y[order])
    model=BeaconLSTM(); opt=torch.optim.Adam(model.parameters(),lr=.01); loss_fn=nn.BCEWithLogitsLoss()
    model.train()
    for _ in range(24):
        opt.zero_grad(); loss=loss_fn(model(X),y); loss.backward(); opt.step()
    Path(model_path).parent.mkdir(parents=True,exist_ok=True)
    torch.save({'state_dict':model.state_dict(),'version':'role3.0.0','sequence_length':seq},model_path)
    return {'trained':True,'path':model_path}

def load_lstm(model_path='models/role3_beacon_lstm.pt'):
    if not TORCH_AVAILABLE or not Path(model_path).exists(): return None
    ckpt=torch.load(model_path,map_location='cpu',weights_only=False); model=BeaconLSTM(); model.load_state_dict(ckpt['state_dict']); model.eval(); return model

def predict_lstm(model, iats):
    if model is None or not TORCH_AVAILABLE or len(iats)<8: return 0.0
    x=np.asarray(iats,dtype='float32')[:32]
    if len(x)<32: x=np.pad(x,(0,32-len(x)),mode='edge')
    with torch.no_grad():
        p=torch.sigmoid(model(torch.tensor(x)[None,:,None])).item()
    return float(p)
