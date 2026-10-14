#!/usr/bin/env python3
"""
Train a simple MalConv-like model from malware/goodware CSVs.

Features:
- Robust CSV loading (dtype=str), column normalization (Full_Path -> File_Path)
- Filters to existing files, drops invalids
- BinaryDataset reading up to max_bytes and normalizing to [0,1]
- Train/val/test split (70/15/15)
- AMP on CUDA when available (safe on CPU)
- tqdm progress bars
- Best checkpoint saving (by val F1) to malconv_model_best.pt and final malconv_model.pt
- Test evaluation with metrics.txt
- Threshold sweep (0.50..0.999) producing threshold_sweep.csv and best_threshold.txt

Usage example:
  python3 train/train_malconv.py \
    --malware-csv /path/malware.csv \
    --goodware-csv /path/goodware.csv \
    --epochs 5 --batch-size 64 --max-bytes 1048576 \
    --out-dir defender/defender/models

CSV schema: expects a path column named File_Path (or Full_Path will be auto-renamed).
"""
from __future__ import annotations

import argparse
import os
import random
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import torch.nn.functional as F
from tqdm import tqdm


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


class BinaryDataset(Dataset):
    def __init__(self, df: pd.DataFrame, max_bytes: int) -> None:
        self.paths = df['File_Path'].tolist()
        self.labels = df['label'].astype(int).tolist()
        self.max_bytes = int(max_bytes)

    def __len__(self) -> int:
        return len(self.paths)

    def __getitem__(self, idx: int):
        path = self.paths[idx]
        y = self.labels[idx]
        if not isinstance(path, str) or not os.path.isfile(path):
            raise FileNotFoundError(f"Invalid path at index {idx}: {path}")
        with open(path, 'rb') as f:
            b = f.read(self.max_bytes)
        if len(b) < self.max_bytes:
            b = b + (b'\x00' * (self.max_bytes - len(b)))
        # NOTE: must stay raw integer byte values (0-255), matching MalConv.embed()'s
        # cast to LongTensor for the nn.Embedding lookup, and matching how the
        # defender's serving code (malconv_model.py's MalConvTorchModel.predict)
        # builds its input. Normalizing to float [0,1] here used to collapse nearly
        # every byte to embedding index 0 once truncated to Long, so the model was
        # effectively trained blind to file content.
        arr = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
        x = torch.from_numpy(arr)
        return x, torch.tensor(y, dtype=torch.float32)


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
        return dense_2_activation.squeeze(1)

    def forward(self, x):
        # x: (batch, seq_len)
        emb_x = self.embed(x, transpose=True)
        return self.embedd_and_forward(emb_x)


def load_data(malware_csv: str, goodware_csv: str) -> pd.DataFrame:
    def read_and_normalize(csv_path: str, label: int) -> pd.DataFrame:
        df = pd.read_csv(csv_path, dtype=str)
        # Normalize path column
        if 'File_Path' not in df.columns and 'Full_Path' in df.columns:
            df = df.rename(columns={'Full_Path': 'File_Path'})
        if 'File_Path' not in df.columns:
            raise ValueError(f"CSV {csv_path} must have 'File_Path' (or 'Full_Path') column")
        df = df[['File_Path']].copy()
        df['label'] = label
        # Clean up
        df['File_Path'] = df['File_Path'].astype(str)
        df = df.dropna(subset=['File_Path'])
        df = df[df['File_Path'].str.len() > 0]
        # Only existing files
        exists_mask = df['File_Path'].apply(lambda p: os.path.isfile(p))
        df = df[exists_mask]
        return df.reset_index(drop=True)

    df_mal = read_and_normalize(malware_csv, 1)
    df_good = read_and_normalize(goodware_csv, 0)
    df = pd.concat([df_mal, df_good], axis=0, ignore_index=True)
    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    print(f"Loaded: malware={len(df_mal)} goodware={len(df_good)} total={len(df)}")
    if len(df) == 0:
        raise RuntimeError("No valid files found after filtering existence checks.")
    print(df.head(5))
    return df


@dataclass
class Split:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def split_df(df: pd.DataFrame, train_frac=0.70, val_frac=0.15) -> Split:
    n = len(df)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    train_df = df.iloc[:n_train]
    val_df = df.iloc[n_train:n_train + n_val]
    test_df = df.iloc[n_train + n_val:]
    print(f"Split sizes: train={len(train_df)} val={len(val_df)} test={len(test_df)}")
    print(f"Train label counts: {train_df['label'].value_counts().to_dict()}")
    print(f"Val label counts: {val_df['label'].value_counts().to_dict()}")
    print(f"Test label counts: {test_df['label'].value_counts().to_dict()}")
    return Split(train=train_df.reset_index(drop=True),
                 val=val_df.reset_index(drop=True),
                 test=test_df.reset_index(drop=True))


def make_loaders(split: Split, max_bytes: int, batch_size: int, num_workers: int, device: torch.device):
    pin = device.type == 'cuda'
    train_loader = DataLoader(BinaryDataset(split.train, max_bytes), batch_size=batch_size, shuffle=True,
                              num_workers=num_workers, pin_memory=pin)
    val_loader = DataLoader(BinaryDataset(split.val, max_bytes), batch_size=batch_size, shuffle=False,
                            num_workers=num_workers, pin_memory=pin)
    test_loader = DataLoader(BinaryDataset(split.test, max_bytes), batch_size=batch_size, shuffle=False,
                             num_workers=num_workers, pin_memory=pin)
    return train_loader, val_loader, test_loader


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, thresh: float) -> Tuple[dict, np.ndarray]:
    y_pred = (y_prob >= thresh).astype(np.int32)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    acc = (tp + tn) / max(1, (tp + tn + fp + fn))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = 2 * prec * rec / max(1e-12, (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = fp / max(1, (fp + tn))
    fnr = fn / max(1, (fn + tp))
    return {
        'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
        'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1,
        'fpr': fpr, 'fnr': fnr
    }, y_pred


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> Tuple[float, np.ndarray, np.ndarray]:
    model.eval()
    loss_fn = nn.BCEWithLogitsLoss()
    losses: List[float] = []
    probs: List[float] = []
    labels: List[int] = []
    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)
            logits = model(x)
            loss = loss_fn(logits, y)
            losses.append(loss.item())
            probs.extend(torch.sigmoid(logits).cpu().numpy().tolist())
            labels.extend(y.cpu().numpy().tolist())
    return float(np.mean(losses) if losses else 0.0), np.array(labels, dtype=np.int32), np.array(probs, dtype=np.float32)



from torch.cuda.amp import autocast, GradScaler
import gc

def train_model(model, train_loader, val_loader, epochs, grad_accum_steps, device, models_dir, optimizer_type='adamw', weight_decay=1e-4, current_month=1):
    # Ensure DataLoaders use pin_memory for faster GPU transfer
    if hasattr(train_loader, 'pin_memory'):
        train_loader.pin_memory = True
    if hasattr(val_loader, 'pin_memory'):
        val_loader.pin_memory = True

    if optimizer_type.lower() == 'adamw':
        print("Using AdamW optimizer with weight decay")
        optimizer = torch.optim.AdamW(model.parameters(), weight_decay=weight_decay)
    else:
        optimizer = torch.optim.Adam(model.parameters())
    criterion = torch.nn.BCEWithLogitsLoss()
    scaler = GradScaler(enabled=(device.type == 'cuda'))
    # Learning rate warmup and dynamic scheduler
    warmup_epochs = 3
    total_epochs = epochs
    cosine_epochs = total_epochs - warmup_epochs
    main_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=cosine_epochs if cosine_epochs > 0 else 1)
    prev_lr = optimizer.param_groups[0]['lr']
    # Early stopping
    patience = 5
    epochs_no_improve = 0
    best_val_loss = float('inf')

    # Create month-specific model directory
    month_models_dir = os.path.join(models_dir, f"Month_{current_month}")
    os.makedirs(month_models_dir, exist_ok=True)
    best_model_path = os.path.join(month_models_dir, "malconv_best.pth")

    for epoch in range(epochs):
        model.train()
        running_loss = 0.0
        optimizer.zero_grad(set_to_none=True)
        # Warmup phase
        if epoch < warmup_epochs:
            print(f"[WARMUP] Epoch {epoch+1}/{epochs} (Warmup Phase)")
            base_lr = optimizer.defaults['lr'] if 'lr' in optimizer.defaults else 1e-3
            warmup_lr = base_lr * (0.1 + 0.9 * (epoch + 1) / warmup_epochs)
            for param_group in optimizer.param_groups:
                param_group['lr'] = warmup_lr
        elif epoch == warmup_epochs:
            print(f"[SCHEDULER] Switching to CosineAnnealingLR for remaining epochs.")
            base_lr = optimizer.defaults['lr'] if 'lr' in optimizer.defaults else 1e-3
            for param_group in optimizer.param_groups:
                param_group['lr'] = base_lr
        train_bar = tqdm(train_loader, desc=f"⚙️  📚  💻 Epoch {epoch+1}/{epochs}", leave=True)
        for i, batch in enumerate(train_bar):
            inputs, labels = batch
            inputs, labels = inputs.to(device, non_blocking=True), labels.to(device, non_blocking=True)
            with autocast(enabled=(device.type == 'cuda')):
                outputs = model(inputs)
                outputs = outputs.squeeze(-1)
                loss = criterion(outputs, labels.float())
                loss = loss / grad_accum_steps
            scaler.scale(loss).backward()
            if (i + 1) % grad_accum_steps == 0:
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
            running_loss += loss.item()
            train_bar.set_postfix({'train_loss': f"{running_loss / (i + 1):.4f}"})
            del inputs, labels, outputs, loss
            torch.cuda.empty_cache()
        # Validation loop
        model.eval()
        val_loss = 0.0
        val_bar = tqdm(val_loader, desc="⚙️  Validation", leave=True)
        with torch.no_grad():
            for batch in val_bar:
                inputs, labels = batch
                inputs, labels = inputs.to(device, non_blocking=True), labels.to(device, non_blocking=True)
                with autocast(enabled=(device.type == 'cuda')):
                    outputs = model(inputs)
                    outputs = outputs.squeeze(-1)
                    loss = criterion(outputs, labels.float())
                val_loss += loss.item()
                val_bar.set_postfix({'val_loss': f"{val_loss / (len(val_bar) - val_bar.n):.4f}"})
                del inputs, labels, outputs, loss
                torch.cuda.empty_cache()
        avg_val_loss = val_loss / len(val_loader)
        # Compute metrics and print TP, FP, TN, FN, FPR, FNR
        model.eval()
        all_labels = []
        all_preds = []
        with torch.no_grad():
            for batch in val_loader:
                inputs, labels = batch
                inputs, labels = inputs.to(device, non_blocking=True), labels.to(device, non_blocking=True)
                outputs = model(inputs)
                outputs = outputs.squeeze(-1)
                preds = torch.round(torch.sigmoid(outputs)).cpu().numpy()
                all_labels.extend(labels.cpu().numpy())
                all_preds.extend(preds)
        import numpy as np
        all_labels = np.array(all_labels, dtype=np.int32)
        all_preds = np.array(all_preds, dtype=np.int32)
        metrics, _ = compute_metrics(all_labels, all_preds, thresh=0.5)
        print(f"Val Metrics: TP={metrics['TP']} FP={metrics['FP']} TN={metrics['TN']} FN={metrics['FN']} FPR={metrics['fpr']:.4f} FNR={metrics['fnr']:.4f}")
        # Step scheduler after warmup
        if epoch >= warmup_epochs:
            main_scheduler.step()
        current_lr = optimizer.param_groups[0]['lr']
        if current_lr != prev_lr:
            print(f"[LR SCHEDULER] Learning rate changed from {prev_lr:.6f} to {current_lr:.6f}")
            prev_lr = current_lr
        # Early stopping logic
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(model.state_dict(), best_model_path)
            print(f"🔥 Saved best model (val_loss: {best_val_loss:.4f}) to {best_model_path}")
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            print(f"No improvement in val_loss for {epochs_no_improve} epoch(s).")
        if epochs_no_improve >= patience:
            print(f"Early stopping triggered after {patience} epochs without improvement.")
            break
        torch.cuda.empty_cache()
        gc.collect()


def threshold_sweep(y_true: np.ndarray, y_prob: np.ndarray, out_dir: str) -> float:
    rows = [("threshold", "f1", "accuracy", "precision", "recall", "fpr", "fnr", "TP", "TN", "FP", "FN")]
    best_thr = 0.5
    best_score = -1.0
    for thr in list(np.arange(0.50, 1.000, 0.005)) + [0.999]:
        m, _ = compute_metrics(y_true, y_prob, thr)
        rows.append((thr, m['f1'], m['accuracy'], m['precision'], m['recall'], m['fpr'], m['fnr'], m['TP'], m['TN'], m['FP'], m['FN']))
        # Preference: meet FPR<=1% and FNR<=10% if possible, else maximize F1
        meets = (m['fpr'] <= 0.01) and (m['fnr'] <= 0.10)
        score = (m['f1'] + 2.0) if meets else m['f1']
        if score > best_score:
            best_score = score
            best_thr = float(thr)
    # Write CSV
    csv_path = os.path.join(out_dir, 'threshold_sweep.csv')
    with open(csv_path, 'w') as f:
        for row in rows:
            if isinstance(row[0], str):
                f.write(','.join(map(str, row)) + '\n')
            else:
                f.write(','.join(map(lambda x: f"{x}", row)) + '\n')
    with open(os.path.join(out_dir, 'best_threshold.txt'), 'w') as f:
        f.write(str(best_thr))
    print(f"Wrote threshold_sweep.csv and best_threshold.txt (best={best_thr}) to {out_dir}")
    return best_thr


def write_metrics(out_dir: str, y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> None:
    m, y_pred = compute_metrics(y_true, y_prob, threshold)
    lines = [
        f"Threshold: {threshold}",
        f"TP: {m['TP']}", f"TN: {m['TN']}", f"FP: {m['FP']}", f"FN: {m['FN']}",
        f"Accuracy: {m['accuracy']:.4f}", f"Precision: {m['precision']:.4f}",
        f"Recall: {m['recall']:.4f}", f"F1: {m['f1']:.4f}",
        f"FPR: {m['fpr']:.4f}", f"FNR: {m['fnr']:.4f}",
    ]
    with open(os.path.join(out_dir, 'metrics.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print("Saved metrics.txt")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train MalConv-like binary classifier")
    ap.add_argument('--malware-csv', required=True, help='CSV of malware file paths')
    ap.add_argument('--goodware-csv', required=True, help='CSV of goodware file paths')
    ap.add_argument('--epochs', type=int, default=3)
    ap.add_argument('--batch-size', type=int, default=64)
    ap.add_argument('--lr', type=float, default=1e-3)
    ap.add_argument('--max-bytes', type=int, default=1_048_576)
    ap.add_argument('--num-workers', type=int, default=16)
    ap.add_argument('--out-dir', default='defender/defender/models', help='Where to save models and metrics')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    set_seed(args.seed)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    df = load_data(args.malware_csv, args.goodware_csv)
    df=df[0:1000]
    split = split_df(df, 0.70, 0.15)
    train_loader, val_loader, test_loader = make_loaders(split, args.max_bytes, args.batch_size, args.num_workers, device)

    use_cuda = device.type == 'cuda'
    model = MalConv(embedding_size=8, max_input_size=args.max_bytes, use_cuda=use_cuda).to(device)

    # Recommended hyperparameters for best performance
    grad_accum_steps = 4  # You can increase for larger batches if you have enough GPU memory
    optimizer_type = 'adamw'
    weight_decay = 1e-4
    current_month = int(pd.Timestamp.now().month)
    train_model(
        model,
        train_loader,
        val_loader,
        epochs=args.epochs,
        grad_accum_steps=grad_accum_steps,
        device=device,
        models_dir=args.out_dir,
        optimizer_type=optimizer_type,
        weight_decay=weight_decay,
        current_month=current_month
    )

    # Load best for testing if present
    best_path = os.path.join(args.out_dir, 'malconv_model_best.pt')
    if os.path.isfile(best_path):
        model.load_state_dict(torch.load(best_path, map_location=device))

    # Test evaluation
    test_loss, y_true, y_prob = evaluate(model, test_loader, device)
    print(f"Test loss: {test_loss:.4f}")
    # Sweep and metrics
    best_thr = threshold_sweep(y_true, y_prob, args.out_dir)
    write_metrics(args.out_dir, y_true, y_prob, best_thr)


if __name__ == '__main__':
    main()
