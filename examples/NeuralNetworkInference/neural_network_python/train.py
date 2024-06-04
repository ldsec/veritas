from pathlib import Path

import numpy as np
import torch
import tqdm as tqdm
from torchvision import datasets
from torchvision.transforms import ToTensor
from tqdm import tqdm

from model import CNN, MAXVAL

torch.manual_seed(0)
np.random.seed(0)

train_data = datasets.MNIST(
    root="../data_python",
    train=True,
    transform=ToTensor(),
    download=True
)

test_data = datasets.MNIST(
    root="../data_python",
    train=False,
    transform=ToTensor(),
    download=True
)


def eval(cnn):
    tp = 0
    n = len(test_data)
    cnn.maxval = 0
    cnn.eval()
    for i, (img, lbl) in enumerate(test_data):
        out = cnn(img.unsqueeze(0))
        pred = out.argmax()
        if pred == lbl:
            tp += 1
    accuracy = float(tp) / n
    print(f"Accuracy (float): {accuracy * 100}%")


def eval_discrete(cnn: CNN, img_scale):
    tp = 0
    n = len(test_data)
    cnn.maxval = 0
    cnn.eval()
    for i, (img, lbl) in enumerate(test_data):
        img = (img * img_scale).long()
        out = cnn(img.unsqueeze(0))
        pred = out.argmax()
        if pred == lbl:
            tp += 1

    accuracy = float(tp) / n
    print(f"Accuracy (discrete): {accuracy * 100}%")
    print(f"Img scale: {img_scale}, Weight scale: {weight_scale} -> max abs value: {cnn.maxval}")
    if cnn.maxval >= MAXVAL:
        print(f"WARNING: max abs value is bigger than t/2 = {MAXVAL}")


def train(cnn):
    # TODO: Use L1-regularization to get sparser weights (and thus maybe more budget for scaling)?
    epochs = 5
    loss_fn = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.SGD(cnn.parameters(), lr=1e-3, momentum=0.9, weight_decay=1e-3)
    loader = torch.utils.data.DataLoader(train_data, batch_size=512, shuffle=True)

    for e in range(epochs):
        cnn.train()
        for img, lbl in tqdm(loader):
            optimizer.zero_grad()

            out = cnn(img)

            loss = loss_fn(out, lbl)

            loss.backward()
            optimizer.step()

            # for p in cnn.parameters():
            #     p.data = cnn.rescale(p.data)
        eval(cnn)
        # for p in cnn.parameters():
        #     p.data = cnn.rescale(p.data)
        # eval(cnn)


if __name__ == "__main__":
    cnn = CNN()
    cnn.requires_grad_(True)
    cnn.check = False

    print("Starting training")
    train(cnn)

    print("Finding optimal scaling parameters")
    img_scale = 2
    weight_scale = 1
    while True:
        tentative_weight_scale = 2 * weight_scale
        print(f"Trying image scale: {img_scale}, weight scale: {tentative_weight_scale}")
        cnn_discrete = cnn.to_discrete(img_scale, tentative_weight_scale)
        cnn_discrete.maxval = 0
        cnn_discrete.check = False

        eval_discrete(cnn_discrete, img_scale)
        new_maxval = cnn_discrete.maxval
        if new_maxval <= MAXVAL:
            print("\tSUCCESS")
            weight_scale = tentative_weight_scale
        else:
            print("\tFAILURE")
            break
    print(f"FINAL image scale: {img_scale}, weight scale: {weight_scale}")

    path = Path(__file__).parent.parent.absolute() / "models" / "LoLa_MNIST"
    cnn.save_csv(path)
    print(f"Weights saved to {path}")
