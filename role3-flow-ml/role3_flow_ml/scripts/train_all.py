import sys
sys.path.insert(0,'src')
from role3_ml.training import train
from role3_ml.sequence_model import train_lstm
train()
print('Role 3 tabular + anomaly demo models trained.')
result=train_lstm()
print('Role 3 LSTM:', result)
