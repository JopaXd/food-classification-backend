from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import HTMLResponse
from keras.models import load_model
from PIL import Image
import numpy as np
import cv2

app = FastAPI()
model = load_model("./model.hdf5")
class_names = open("./class_names.txt", "r").readlines()

@app.post('/classify')
def classify_image(img: UploadFile = File(...)):
    img = Image.open(img.file)
    img = np.array(img)
    img = cv2.cvtColor(np.array(img), cv2.COLOR_BGR2RGB)
    img = cv2.resize(img, dsize=(128,128), interpolation = cv2.INTER_CUBIC)
    img = np.expand_dims(img,axis=0)
    prediction = model.predict(img)
    result = class_names[np.argmax(prediction)].rstrip()
    return {"prediction" : result}
