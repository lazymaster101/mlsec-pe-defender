import os
from typing import Dict

import numpy as np
import torch
import torch.nn as nn


class _MalConv(nn.Module):
    def __init__(self, max_bytes: int):
        super().__init__()
        self.max_bytes = max_bytes
        self.conv1 = nn.Conv1d(1, 16, kernel_size=500, stride=500)
        self.relu = nn.ReLU()
        self.fc1 = nn.Linear(16 * (self.max_bytes // 500), 64)
        self.fc2 = nn.Linear(64, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, bytes)
        x = x.unsqueeze(1)  # (batch, 1, bytes)
        x = self.conv1(x)
        x = self.relu(x)
        x = x.view(x.size(0), -1)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x.squeeze(1)  # logits


class MalConvTorchModel:
    """
    Minimal wrapper expected by defender.apps.create_app:
      - predict(bytez: bytes) -> int in {0,1}
      - model_info() -> dict
    """

    def __init__(
        self,
        weights_path: str,
        max_bytes: int = 1_048_576,
        threshold: float = 0.5,
        device: str = 'cpu',
    ) -> None:
        self.name = 'malconv'
        self.max_bytes = int(max_bytes)
        self.threshold = float(threshold)
        self.device = torch.device(device)

        self.model = _MalConv(self.max_bytes).to(self.device)
        self.model.eval()

        if not os.path.isabs(weights_path):
            # If a bare filename is passed, resolve relative to the models directory
            # Do not preprend an extra 'models' segment
            base = os.path.dirname(os.path.abspath(__file__))
            weights_path = os.path.join(base, weights_path)

        if not os.path.isfile(weights_path):
            raise FileNotFoundError(f"MalConv weights not found: {weights_path}")

        state = torch.load(weights_path, map_location=self.device)
        # Support saving state_dict directly or wrapped
        if isinstance(state, dict) and 'state_dict' in state:
            state = state['state_dict']
        self.model.load_state_dict(state)

    @torch.no_grad()
    def predict(self, bytez: bytes) -> int:
        # Preprocess to fixed-size float tensor in [0,1]
        b = bytez[: self.max_bytes]
        if len(b) < self.max_bytes:
            b = b + (b'\x00' * (self.max_bytes - len(b)))

        arr = np.frombuffer(b, dtype=np.uint8).astype(np.float32) / 255.0
        t = torch.from_numpy(arr).to(self.device)
        t = t.unsqueeze(0)  # (1, bytes)

        logit = self.model(t)
        prob = torch.sigmoid(logit).item()
        return int(prob >= self.threshold)

    def model_info(self) -> Dict:
        return {
            'name': self.name,
            'max_bytes': self.max_bytes,
            'threshold': self.threshold,
            'device': str(self.device),
        }
