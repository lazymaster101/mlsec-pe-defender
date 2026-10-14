import torch
import torch.nn as nn
from torch.cuda.amp import GradScaler, autocast
from torch.utils.data import DataLoader
from tqdm import tqdm
from sklearn.metrics import accuracy_score, f1_score
import gc
import os
debug_mode=True
# --- Official MalConv Implementation ---
import torch.nn.functional as F

# Commented out old MalConvBase implementation above
# class MalConvBase(nn.Module):
#     ...

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

class ModelTrainer:
    def load_weights(self, weights_path: str):
        """
        Load model weights from the specified path.
        Args:
            weights_path (str): Path to the .pth file containing model weights.
        """
        if not os.path.exists(weights_path):
            raise FileNotFoundError(f"Weights file not found: {weights_path}")
        self.model.load_state_dict(torch.load(weights_path, map_location=self.device, weights_only=True))
        print(f"[INFO] Loaded weights from {weights_path}")
    """A class for training and managing the MalConv model for malware detection."""

    def __init__(self, embed_dim: int = 8, out_channels: int = 128, window_size: int = 32,
                 dropout: float = 0.5, device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
                 models_dir: str = "models", optimizer_type: str = 'adamw', weight_decay: float = 1e-4):
        """
        Initialize the ModelTrainer with MalConv parameters and directory settings.

        Args:
            embed_dim (int): Embedding dimension for MalConv. Defaults to 8.
            out_channels (int): Number of output channels for convolution. Defaults to 128.
            window_size (int): Convolution window size. Defaults to 32.
            dropout (float): Dropout rate. Defaults to 0.5.
            device (str): Device to train on ('cuda' or 'cpu'). Defaults to 'cuda' if available.
            models_dir (str): Base directory for saving models. Defaults to 'models'.
        """
        # Use official MalConv implementation
        use_cuda = device == 'cuda'
        self.model = MalConv(embedding_size=embed_dim, use_cuda=use_cuda).to(device)
        self.device = device
        self.models_dir = models_dir
        self.optimizer_type = optimizer_type
        self.weight_decay = weight_decay
        os.makedirs(self.models_dir, exist_ok=True)
        # Print model architecture in debug mode
        if debug_mode:
            print("\n[DEBUG] MalConv Model Architecture:")
            print(self.model)

    def _shutdown_dataloader_workers(self, loader: DataLoader) -> None:
        """Shutdown DataLoader workers to free resources."""
        if hasattr(loader, 'dataset') and hasattr(loader.dataset, '_iterator'):
            loader.dataset._iterator._shutdown_workers()

    def train_model(self, train_loader: DataLoader, val_loader: DataLoader,
                    epochs: int, grad_accum_steps: int, current_month: int) -> None:
        # Ensure DataLoaders use pin_memory for faster GPU transfer
        if hasattr(train_loader, 'pin_memory'):
            train_loader.pin_memory = True
        if hasattr(val_loader, 'pin_memory'):
            val_loader.pin_memory = True
        """
        Train the MalConv model with progress tracking, learning rate scheduling, and early stopping.

        Args:
            train_loader (DataLoader): Training data loader (byte-based).
            val_loader (DataLoader): Validation data loader (byte-based).
            epochs (int): Number of training epochs.
            grad_accum_steps (int): Number of steps for gradient accumulation.
            current_month (int): Current month for saving model to Month_X directory.
        """
        if self.optimizer_type.lower() == 'adamw':
            print("Using AdamW optimizer with weight decay")
            optimizer = torch.optim.AdamW(self.model.parameters(), weight_decay=self.weight_decay)
        else:
            optimizer = torch.optim.Adam(self.model.parameters())
        criterion = torch.nn.BCEWithLogitsLoss()
        scaler = GradScaler(enabled=(self.device == 'cuda'))
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
        month_models_dir = os.path.join(self.models_dir, f"Month_{current_month}")
        os.makedirs(month_models_dir, exist_ok=True)
        best_model_path = os.path.join(month_models_dir, "malconv_best.pth")

        # For plotting running loss
        train_loss_history = []

        for epoch in range(epochs):
            self.model.train()
            running_loss = 0.0
            optimizer.zero_grad(set_to_none=True)
            # Warmup phase
            if epoch < warmup_epochs:
                print(f"[WARMUP] Epoch {epoch+1}/{epochs} (Warmup Phase)")
                # Linearly increase LR from 10% to base LR
                base_lr = optimizer.defaults['lr'] if 'lr' in optimizer.defaults else 1e-3
                warmup_lr = base_lr * (0.1 + 0.9 * (epoch + 1) / warmup_epochs)
                for param_group in optimizer.param_groups:
                    param_group['lr'] = warmup_lr
            elif epoch == warmup_epochs:
                print(f"[SCHEDULER] Switching to CosineAnnealingLR for remaining epochs.")
                # Reset LR to base LR before starting main scheduler
                base_lr = optimizer.defaults['lr'] if 'lr' in optimizer.defaults else 1e-3
                for param_group in optimizer.param_groups:
                    param_group['lr'] = base_lr
            # Training loop with tqdm and fire emoji
            train_bar = tqdm(train_loader, desc=f"⚙️  📚  💻 Epoch {epoch+1}/{epochs}", leave=True)
            for i, batch in enumerate(train_bar):
                inputs, labels = batch
                inputs, labels = inputs.to(self.device, non_blocking=True), labels.to(self.device, non_blocking=True)
                with autocast(enabled=(self.device == 'cuda')):
                    outputs = self.model(inputs)
                    outputs = outputs.squeeze(-1)  # Ensure shape [batch]
                    loss = criterion(outputs, labels.float())
                    loss = loss / grad_accum_steps
                scaler.scale(loss).backward()
                if (i + 1) % grad_accum_steps == 0:
                    scaler.step(optimizer)
                    scaler.update()
                    optimizer.zero_grad(set_to_none=True)
                running_loss += loss.item() * grad_accum_steps
                train_bar.set_postfix({'train_loss': f"{running_loss / (i + 1):.4f}"})
                del inputs, labels, outputs, loss
                torch.cuda.empty_cache()
            # Save average running loss for this epoch
            avg_train_loss = running_loss / len(train_loader)
            train_loss_history.append(avg_train_loss)
            # Validation loop with tqdm
            self.model.eval()
            val_loss = 0.0
            val_bar = tqdm(val_loader, desc="⚙️  Validation", leave=True)
            with torch.no_grad():
                for batch in val_bar:
                    inputs, labels = batch
                    inputs, labels = inputs.to(self.device, non_blocking=True), labels.to(self.device, non_blocking=True)
                    with autocast(enabled=(self.device == 'cuda')):
                        outputs = self.model(inputs)
                        outputs = outputs.squeeze(-1)  # Ensure shape [batch]
                        loss = criterion(outputs, labels.float())
                    val_loss += loss.item()
                    val_bar.set_postfix({'val_loss': f"{val_loss / (len(val_bar) - val_bar.n):.4f}"})
                    del inputs, labels, outputs, loss
                    torch.cuda.empty_cache()
            avg_val_loss = val_loss / len(val_loader)
            # Step scheduler after warmup
            if epoch >= warmup_epochs:
                main_scheduler.step()
            # Print when learning rate changes
            current_lr = optimizer.param_groups[0]['lr']
            if current_lr != prev_lr:
                print(f"[LR SCHEDULER] Learning rate changed from {prev_lr:.6f} to {current_lr:.6f}")
                prev_lr = current_lr
            # Early stopping logic
            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                torch.save(self.model.state_dict(), best_model_path)
                print(f"🔥 Saved best model (val_loss: {best_val_loss:.4f}) to {best_model_path}")
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                print(f"No improvement in val_loss for {epochs_no_improve} epoch(s).")
            if epochs_no_improve >= patience:
                print(f"Early stopping triggered after {patience} epochs without improvement.")
                break
            # Clean up after epoch
            self._shutdown_dataloader_workers(train_loader)
            self._shutdown_dataloader_workers(val_loader)
            torch.cuda.empty_cache()
            gc.collect()

        # Plot and save training loss curve
        try:
            import matplotlib.pyplot as plt
            plt.figure()
            plt.plot(range(1, len(train_loss_history)+1), train_loss_history, marker='o')
            plt.xlabel('Epoch')
            plt.ylabel('Training Loss')
            plt.title('Training Loss Curve')
            plt.grid(True)
            plt.tight_layout()
            plot_path = os.path.join(month_models_dir, 'training_loss_curve.png')
            plt.savefig(plot_path)
            plt.close()
            print(f"[INFO] Training loss curve saved to {plot_path}")
        except Exception as e:
            print(f"[WARNING] Could not save training loss plot: {e}")

    def evaluate_model(self, test_loader: DataLoader) -> tuple:
        """
        Evaluate the MalConv model on a test dataset.

        Args:
            test_loader (DataLoader): Test data loader (byte-based).

        Returns:
            tuple: (accuracy, f1, predictions, true_labels)
        """
        self.model.eval()
        predictions = []
        true_labels = []
        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Testing", leave=False):
                inputs, labels = batch
                inputs, labels = inputs.to(self.device, non_blocking=True), labels.to(self.device, non_blocking=True)
                with autocast(enabled=(self.device == 'cuda')):  # Fixed autocast syntax
                    outputs = self.model(inputs)
                    preds = (torch.sigmoid(outputs) > 0.5).float()
                predictions.extend(preds.cpu().numpy())
                true_labels.extend(labels.cpu().numpy())
                del inputs, labels, outputs, preds
                torch.cuda.empty_cache()

        accuracy = accuracy_score(true_labels, predictions)
        f1 = f1_score(true_labels, predictions)
        return accuracy, f1, predictions, true_labels

    def test_single_sample(self, sample, label=None) -> dict:
        """
        Run inference on a single sample (one byte sequence) and return prediction details.

        Args:
            sample (torch.Tensor or np.ndarray): Single sample shaped either (1, seq_len) or (seq_len,) or
                a tensor of Long type with values in [0,256].
            label (int, optional): True label if available (0 or 1). If provided, 'correct' will be included in
                the returned dict.

        Returns:
            dict: {
                'probability': float,  # sigmoid probability
                'prediction': int,      # 0 or 1
                'label': int or None,   # provided label
                'correct': bool or None # whether prediction == label when label provided
            }
        """
        # Prepare input tensor
        if not isinstance(sample, torch.Tensor):
            try:
                sample = torch.from_numpy(sample)
            except Exception:
                raise TypeError("sample must be a torch.Tensor or numpy.ndarray")
        # Ensure batch dimension
        if sample.dim() == 1:
            sample = sample.unsqueeze(0)
        elif sample.dim() == 2 and sample.size(0) != 1:
            # If a batch was passed, just take the first element
            sample = sample[0].unsqueeze(0)

        sample = sample.to(self.device)
        self.model.eval()
        with torch.no_grad():
            with autocast(enabled=(self.device == 'cuda')):
                outputs = self.model(sample)
                prob = torch.sigmoid(outputs).squeeze().item()
                pred = int(prob > 0.5)

        result = {
            'probability': prob,
            'prediction': pred,
            'label': None,
            'correct': None,
        }
        if label is not None:
            result['label'] = int(label)
            result['correct'] = (result['prediction'] == result['label'])

        return result
