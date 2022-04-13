from fastapi import FastAPI, File, HTTPException, UploadFile, Form, status, Body, Cookie, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from keras.models import load_model
from pymongo import MongoClient
from pydantic import BaseModel
from PIL import Image
import numpy as np
import bcrypt
import cv2
import jwt
import datetime

app = FastAPI()
mgClient = MongoClient('localhost', 27017)
db = mgClient['food-classification']
usersCollection = db['users']
model = load_model("./model.hdf5")
class_names = open("./class_names.txt", "r").readlines()


origins = [
    "http://localhost",
    "http://localhost:4200"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class JWTAuth:
    def __init__(self, key):
        self.key = key

    def create_access_token(self, subject):
        return jwt.encode(
            {"exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=1), "subject": subject},
            self.key,
        )

    def create_refresh_token(self, subject):
        return jwt.encode(
            {"exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=30), "subject": subject},
            self.key,
        )

    def refresh_token(self, refresh_token):
        subject = jwt.decode(refresh_token, self.key)
        return self.create_access_token(subject)

    def decode(self, token):
        return jwt.decode(token, self.key)["subject"]

    def check_token(self, token):
        try:
            jwt.decode(token, self.key)
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.exceptions.DecodeError:
            return False

    def login_required(self, access_token = Cookie(None)):
        if self.check_token(access_token) == False:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Failed to authorize!")

    #For the login route.
    def logged_in_not_allowed(self, access_token=Cookie(None)):
        if self.check_token(access_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authorized cannot access this route!")

# IN PPRODUCTION THIS SHOULD BE STORED IN AN ENV VARIABLE.
jwt_helper = JWTAuth("p7BHaDz1oWmaB13HOTotwq4Y4F+Bns/K")

@app.post("/signup")
def signup(email: str = Body(...), password:str = Body(...)):
    if usersCollection.find_one({"email": email}) == None:
        hashedPwd = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        usersCollection.insert_one({"email": email, "password": hashedPwd})
        return Response(status_code=status.HTTP_201_CREATED, content={"status": "ok!"})
        #Login the user automatically when i add JWT.
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists!")        

@app.post("/authenticate", dependencies=[Depends(jwt_helper.logged_in_not_allowed)])
def authenticate(email: str = Body(...), password:str = Body(...)):
    if (user := usersCollection.find_one({"email": email})) != None:
        if bcrypt.checkpw(password.encode(), user["password"]):
            access_token = jwt_helper.create_access_token({"email": email})
            refresh_token = jwt_helper.create_refresh_token({"email": email})
            response = JSONResponse(content={"status": "ok!"}, status_code=status.HTTP_200_OK)
            response.set_cookie(key="access_token", value=access_token.decode("utf-8"), httponly=True)
            response.set_cookie(key="refresh_token", value=refresh_token.decode("utf-8"), httponly=True)
            return response
            #Authenticated.
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Failed to authenticate!")
            #Failed to authenticate, passwords don't match.
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found!")

#Refresh route shouldn't be protected
#Because, if the access token is invalid,
#Then the user wouldn't even be able to refresh it.
@app.get("/refresh")
def refresh(refresh_token = Cookie(None)):
    try:
        new_access_token = jwt_helper.refresh_token(refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Refresh token expired!")
        return response
    response = JSONResponse(content={"status": "ok!"}, status_code=status.HTTP_200_OK)
    response.set_cookie(key="access_token", value=new_access_token, httponly=True)
    return response

@app.get("/users/me")
def get_current_user(access_token = Cookie(None)):
    if jwt_helper.check_token(access_token):
        current_user = jwt_helper.decode(access_token)
        response = JSONResponse(content=current_user, status_code=status.HTTP_200_OK)
        return response
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token expired!")


@app.post("/classify", dependencies=[Depends(jwt_helper.login_required)])
def classify_image(img: UploadFile = File(...)):
    img = Image.open(img.file)
    img = np.array(img)
    img = cv2.cvtColor(np.array(img), cv2.COLOR_BGR2RGB)
    img = cv2.resize(img, dsize=(128,128), interpolation = cv2.INTER_CUBIC)
    img = np.expand_dims(img,axis=0)
    prediction = model.predict(img)
    result = class_names[np.argmax(prediction)].rstrip()
    return {"prediction" : result}