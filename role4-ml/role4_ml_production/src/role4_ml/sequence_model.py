from __future__ import annotations

import os
from typing import Iterable, Tuple

import numpy as np
import torch
from torch import nn


class SequenceLSTM(nn.Module):
    def __init__(self, input_dim: int = 2, hidden_dim: int = 32, num_layers: int = 1, classes: int = 3):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=num_layers, batch_first=True)
        self.head = nn.Sequential(nn.Linear(hidden_dim, 32), nn.ReLU(), nn.Dropout(0.1), nn.Linear(32, classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, _ = self.lstm(x)
        return self.head(out[:, -1, :])


def train_sequence_model(X: np.ndarray, y: np.ndarray, path: str, classes: int = 3, epochs: int = 10) -> None:
    model = SequenceLSTM(classes=classes)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()
    tx = torch.tensor(X, dtype=torch.float32)
    ty = torch.tensor(y, dtype=torch.long)
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(tx)
        loss = loss_fn(logits, ty)
        loss.backward()
        optimizer.step()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "classes": classes, "input_dim": 2}, path)


def load_sequence_model(path: str, classes: int = 3) -> SequenceLSTM:
    model = SequenceLSTM(classes=classes)
    payload = torch.load(path, map_location="cpu", weights_only=False)
    model.load_state_dict(payload["state_dict"])
    model.eval()
    return model


def predict_sequence(model: SequenceLSTM, matrix: np.ndarray) -> Tuple[int, np.ndarray]:
    with torch.no_grad():
        logits = model(torch.tensor(matrix[None, ...], dtype=torch.float32))
        probs = torch.softmax(logits, dim=-1).numpy()[0]
    return int(np.argmax(probs)), probs
