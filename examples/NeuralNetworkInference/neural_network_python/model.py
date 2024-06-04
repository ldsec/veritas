from pathlib import Path

import torch
import torch.nn as nn
from torchvision import datasets
from torchvision.transforms import ToTensor

from weights import *

np.seterr(all='warn')

test_data = datasets.MNIST(
    root="dataPy",
    train=False,
    transform=ToTensor(),
    download=True
)

MAXVAL = 4293918721 / 2


class CNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.maxval = 0
        self.check = True

        self.conv1 = nn.Conv2d(
            in_channels=1,
            out_channels=5,
            kernel_size=5,
            stride=2,
            padding=1,
        )

        self.lin1 = nn.Linear(in_features=845, out_features=100)
        self.lin2 = nn.Linear(in_features=100, out_features=10)

    @staticmethod
    def rescale(t: torch.Tensor):
        res = 2 * (t - t.min()) / (t.max() - t.min()) - 1
        assert (res.min() + 1).abs() < 1e-6
        assert (res.max() - 1).abs() < 1e-6
        res.clamp_(-1, 1)
        return res

    def to_discrete(self, img_scale, weight_scale, maxval=0, check=False):
        cnn = CNN()
        cnn.requires_grad_(False)
        cnn.maxval = maxval
        cnn.check = check
        s = img_scale

        cnn.conv1.weight.data = (self.rescale(self.conv1.weight.clone().data) * weight_scale).long()
        cnn.conv1.bias.data = (self.rescale(self.conv1.bias.clone().data) * weight_scale * s).long()

        s *= weight_scale  # after conv
        s *= s  # after square

        cnn.lin1.weight.data = (self.rescale(self.lin1.weight.clone().data) * weight_scale).long()
        cnn.lin1.bias.data = (self.rescale(self.lin1.bias.clone().data) * weight_scale * s).long()

        s *= weight_scale
        s *= s

        cnn.lin2.weight.data = (self.rescale(self.lin2.weight.clone().data) * weight_scale).long()
        cnn.lin2.bias.data = (self.rescale(self.lin2.bias.clone().data) * weight_scale * s).long()

        return cnn

    def forward(self, x):
        x = self.conv1(x)
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        x = torch.flatten(x, 1)
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        x = x * x
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        x = self.lin1(x)
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        x = x * x
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        x = self.lin2(x)
        self.maxval = max(x.abs().max().item(), self.maxval)
        assert not self.check or self.maxval < MAXVAL

        return x

    def save_csv(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        for name, t in self.named_parameters():
            filename = name + ".csv"
            with open(path / filename, "w+") as f:
                f.write(",".join(str(x.item()) for x in t.flatten()))


if __name__ == "__main__":
    img_scale = 6
    s = img_scale
    weight_scale = 6

    cnn = CNN()
    cnn.requires_grad_(False)

    cnn.conv1.weight.data = torch.tensor((np.reshape(weightsConv, (5, 1, 5, 5)) * weight_scale)).long()
    cnn.conv1.bias.data = torch.tensor(np.reshape(biasConv, (5,)) * weight_scale * s).long()

    s *= weight_scale  # after conv
    s *= s  # after square

    cnn.lin1.weight.data = torch.tensor(np.reshape(weightsLin1, (100, 845)) * weight_scale).long()
    cnn.lin1.bias.data = torch.tensor(np.reshape(biasLin1, (100,)) * weight_scale * s).long()

    s *= weight_scale
    s *= s

    cnn.lin2.weight.data = torch.tensor(np.reshape(weightsLin2, (10, 100)) * weight_scale).long()
    cnn.lin2.bias.data = torch.tensor(np.reshape(biasLin2, (10,)) * weight_scale * s).long()

    s *= weight_scale

    tp = 0
    n = len(test_data)

    for i, (img, lbl) in enumerate(test_data):
        img = (img * img_scale).long()
        out = cnn(img.unsqueeze(0))
        pred = out.argmax()
        if pred == lbl:
            tp += 1
        # print(f"Image #{i}: {[f'{p / s:4.3f}' for p in out.tolist()]}")
        print(f"Image #{i}: was {lbl}, predicted {pred}")

    accuracy = float(tp) / n
    print(f"Accuracy: {accuracy * 100}%")
    print(f"Img scale: {img_scale}, Weight scale: {weight_scale} -> max abs value: {cnn.maxval} (< t/2 = {MAXVAL})")
