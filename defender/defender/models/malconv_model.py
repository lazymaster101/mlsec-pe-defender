import os
from typing import Dict
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

class End2EndModel(nn.Module):
    def __init__(self, embedding_size, max_input_size, num_classes, use_softmax):
        super(End2EndModel, self).__init__()
        self.embedding_size = embedding_size
        self.max_input_size = max_input_size
        self.num_classes = num_classes
        self.use_softmax = use_softmax

class MalConv(End2EndModel):
    """
    Official MalConv architecture implementation.
    """
    def __init__(self, pretrained_path=None, embedding_size=8, max_input_size=2 ** 20, use_cuda=False):
        super(MalConv, self).__init__(embedding_size, max_input_size, 256, False)
        self.embedding_1 = nn.Embedding(num_embeddings=257, embedding_dim=embedding_size)
        self.conv1d_1 = nn.Conv1d(in_channels=embedding_size, out_channels=128, kernel_size=(500,), stride=(500,), groups=1, bias=True)
        self.conv1d_2 = nn.Conv1d(in_channels=embedding_size, out_channels=128, kernel_size=(500,), stride=(500,), groups=1, bias=True)
        self.dense_1 = nn.Linear(in_features=128, out_features=128, bias=True)
        self.dense_2 = nn.Linear(in_features=128, out_features=1, bias=True)
        if pretrained_path is not None:
            self.load_simplified_model(pretrained_path)
        self.use_cuda = use_cuda
        if self.use_cuda:
            self.cuda()

    def embed(self, input_x, transpose=True):
        if isinstance(input_x, torch.Tensor):
            x = input_x.clone().detach().type(torch.LongTensor)
        else:
            x = torch.from_numpy(input_x).type(torch.LongTensor)
        x = x.squeeze(dim=1)
        if self.use_cuda:
            x = x.cuda()
        emb_x = self.embedding_1(x)
        if transpose:
            emb_x = torch.transpose(emb_x, 1, 2)
        return emb_x

    def embedd_and_forward(self, x):
        conv1d_1 = self.conv1d_1(x)
        conv1d_2 = self.conv1d_2(x)
        conv1d_1_activation = torch.relu(conv1d_1)
        conv1d_2_activation = torch.sigmoid(conv1d_2)
        multiply_1 = conv1d_1_activation * conv1d_2_activation
        global_max_pooling1d_1 = F.max_pool1d(input=multiply_1, kernel_size=multiply_1.size()[2:])
        global_max_pooling1d_1_flatten = global_max_pooling1d_1.view(global_max_pooling1d_1.size(0), -1)
        dense_1 = self.dense_1(global_max_pooling1d_1_flatten)
        dense_1_activation = torch.relu(dense_1)
        dense_2 = self.dense_2(dense_1_activation)
        dense_2_activation = torch.sigmoid(dense_2)
        return dense_2_activation

    def forward(self, x):
        # x: (batch, seq_len)
        emb_x = self.embed(x, transpose=True)
        return self.embedd_and_forward(emb_x)

class MalConvTorchModel:
    """
    Minimal wrapper expected by defender.apps.create_app:
      - predict(bytez: bytes) -> int in {0,1}
      - model_info() -> dict
    """
    def __init__(self,
        weights_path: str,
        max_bytes: int = 2 ** 20,
        threshold: float = 0.5,
        device: str = 'cpu',
    ) -> None:
        self.name = 'malconv'
        self.max_bytes = int(max_bytes)
        self.threshold = float(threshold)
        self.device = torch.device(device)
        self.model = MalConv(
            pretrained_path=None,
            embedding_size=8,
            max_input_size=self.max_bytes,
            use_cuda=(device == 'cuda')
        ).to(self.device)
        self.model.eval()
        if not os.path.isabs(weights_path):
            base = os.path.dirname(os.path.abspath(__file__))
            weights_path = os.path.join(base, weights_path)
        if not os.path.isfile(weights_path):
            raise FileNotFoundError(f"MalConv weights not found: {weights_path}")
        # weights_only=True restricts unpickling to tensors/plain data, so a weights
        # file from an untrusted or third-party source can't smuggle in arbitrary
        # code via pickle's __reduce__ mechanism.
        state = torch.load(weights_path, map_location=self.device, weights_only=True)
        if isinstance(state, dict) and 'state_dict' in state:
            state = state['state_dict']
        self.model.load_state_dict(state)

    @torch.no_grad()
    def predict(self, bytez: bytes) -> int:
        b = bytez[: self.max_bytes]
        if len(b) < self.max_bytes:
            b = b + (b'\x00' * (self.max_bytes - len(b)))
        arr = np.frombuffer(b, dtype=np.uint8)
        arr = arr.astype(np.int64)
        arr[arr > 255] = 256
        arr = arr.reshape(1, -1)
        t = torch.from_numpy(arr).to(self.device)
        logit = self.model(t)
        prob = logit.item() if hasattr(logit, 'item') else logit.squeeze().item()
        return int(prob >= self.threshold)

    def model_info(self) -> Dict:
        return {
            'name': self.name,
            'max_bytes': self.max_bytes,
            'threshold': self.threshold,
            'device': str(self.device),
        }
