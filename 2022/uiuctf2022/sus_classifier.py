# sus ones have distinctly different outputs from rest
# uiuctf{2_31_41_59_65}

import torch
import torch.nn as nn
import torchvision
import torch.nn.functional as F
import os
from PIL import Image

IMAGE_DIR = './crewmates/'
MODEL_PATH = './partial_sus_detector.pt'

# load all images into memory
def load_images(path):
    images = []
    paths = []
    for filename in os.listdir(path):
        paths.append(filename)
    paths.sort()

    for filename in paths:
        im = Image.open(path + filename)
        images.append(im)

    transforms = torchvision.transforms.ToTensor()
    players = [transforms(image) for image in images]
    players = torch.stack(players)
    return players

# A partial classifier
class PartialModel(nn.Module):
    def __init__(self, input_channels):
        super(PartialModel, self).__init__()
        self.conv1 = nn.Conv2d(input_channels, 32, 3, padding=1)
        self.conv2 = nn.Conv2d(32, 32, 3, padding=1)
        self.conv3 = nn.Conv2d(32, 32, 3, padding=1)
        self.conv4 = nn.Conv2d(32, 64, 3, padding=1)
        self.pooling = nn.MaxPool2d(2, 2)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = self.pooling(x)
        x = F.relu(self.conv2(x))
        x = self.pooling(x)
        x = F.relu(self.conv3(x))
        x = F.relu(self.conv4(x))
        x = self.pooling(x)
        return x

partial_model = PartialModel(3)
partial_model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device('cpu')))
partial_model.eval()

crewmates = load_images(IMAGE_DIR)

partial_outputs = partial_model(crewmates)
for i, p in enumerate(partial_outputs):
    print(i)
    print(sum(sum(sum(y for y in x) for x in p)))
