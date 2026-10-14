#!/usr/bin/env python3
import argparse
import torch
from train_malconv import load_data, BinaryDataset, MalConv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--malware-csv', required=True)
    ap.add_argument('--goodware-csv', required=True)
    ap.add_argument('--max-bytes', type=int, default=1_048_576)
    args = ap.parse_args()

    df = load_data(args.malware_csv, args.goodware_csv)
    ds = BinaryDataset(df.head(8), args.max_bytes)
    x, y = ds[0]
    print('Sample tensor:', x.shape, 'label:', y.item())
    m = MalConv(args.max_bytes)
    with torch.no_grad():
        logits = m(x.unsqueeze(0))
        print('Logits:', logits)


if __name__ == '__main__':
    main()
from train_malconv import load_data, BinaryDataset
from torch.utils.data import DataLoader

if __name__ == "__main__":
    df = load_data()
    print(f"Dataframe rows after cleaning: {len(df)}")
    ds = BinaryDataset(df)
    dl = DataLoader(ds, batch_size=2, shuffle=True, num_workers=0)
    X, y = next(iter(dl))
    print("Got batch:", X.shape, y.shape, X.dtype, y.dtype)
    # Print first paths for manual verification
    print(df[['File_Path', 'label']].head(5).to_string(index=False))
