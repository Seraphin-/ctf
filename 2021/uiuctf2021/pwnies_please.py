# pwnies_please (Misc 390)
# adapted from examples of torchattacks
# uiuctf{th4nks_f0r_th3_pwni3s}

from torchvision import models
import torchvision.transforms as transforms
import torchvision 
import torch.nn as nn
import torch
import numpy as np
from PIL import Image
import time
import io

# ------------------ Model goes here ⬇------------------ #
imagenet_class_index = ['plane', 'car', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck']
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

model_ = models.resnet18()
num_ftrs = model_.fc.in_features
model_.fc = nn.Linear(num_ftrs, len(imagenet_class_index))
model_.load_state_dict(torch.load("./models/pwny_cifar_eps_0.pth", map_location = device))
model_ft = model_.to(device)

norm_layer = transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
model = nn.Sequential(
    norm_layer,
    model_
).to(device)
model.eval()

def tensor_to_image(tensor):
    tensor = tensor.detach().squeeze().numpy()
    tensor = tensor.transpose(1, 2, 0)
    tensor = (tensor * 255).astype(np.uint8)
    return Image.fromarray(tensor)

def image_to_tensor(img):
    tensor = np.array(img).astype(np.float32) / 255.0
    # HWC -> CHW
    tensor = tensor.transpose(2, 0, 1)
    tensor = tensor[None, :, :, :]  # add batch dimension
    return torch.tensor(tensor, requires_grad=True)

from torchattacks import *
atk = FGSM(model, eps=16/255)

def go(data):
    images = image_to_tensor(Image.open(io.BytesIO(data)))
    labels = torch.tensor([imagenet_class_index.index("horse")])
    adv_images = atk(images, labels)
    labels = labels.to(device)
    outputs = model(adv_images)

    _, pre = torch.max(outputs.data, 1)
    a = io.BytesIO()
    tensor_to_image(adv_images.cpu().data).save(a, format='png')
    return a.getvalue()

import requests
import base64

s = requests.Session()
resp = s.get("http://pwnies-please.chal.uiuc.tf/").text
while "uiuctf" not in resp:
    image = base64.b64decode(resp.split("data:image/png;base64,")[1].split('"')[0])
    image = go(image)
    resp = s.post("http://pwnies-please.chal.uiuc.tf/", files={"file":("pwny.png",image,"image/png")}).text
    print(resp.split('response">')[1].split("<")[0])
