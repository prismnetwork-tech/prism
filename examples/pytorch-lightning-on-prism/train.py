"""A minimal PyTorch Lightning training job, meant to run on a leased Prism GPU.

It trains a tiny autoencoder on synthetic data for a few epochs and prints the
device it used, so the run visibly exercises the leased GPU. Real Lightning code;
nothing here is Prism-specific.
"""

import lightning as L
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset


class LitAutoEncoder(L.LightningModule):
    def __init__(self) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 32))

    def training_step(self, batch, _batch_idx):
        (x,) = batch
        loss = nn.functional.mse_loss(self.net(x), x)
        self.log("train_loss", loss, prog_bar=True)
        return loss

    def configure_optimizers(self):
        return torch.optim.Adam(self.parameters(), lr=1e-3)


def main() -> None:
    torch.manual_seed(0)
    loader = DataLoader(TensorDataset(torch.randn(512, 32)), batch_size=64)

    cuda = torch.cuda.is_available()
    device = torch.cuda.get_device_name(0) if cuda else "cpu"
    print(f"cuda_available={cuda} device={device}", flush=True)

    trainer = L.Trainer(
        max_epochs=3,
        accelerator="gpu" if cuda else "cpu",
        devices=1,
        enable_checkpointing=False,
        logger=False,
    )
    trainer.fit(LitAutoEncoder(), loader)
    print("training_complete", flush=True)


if __name__ == "__main__":
    main()
