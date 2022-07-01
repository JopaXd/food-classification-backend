from fastapi import FastAPI, File, HTTPException, UploadFile, Form, status, Body, Cookie, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from keras.models import load_model
from pymongo import MongoClient
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
likedPostsCollection = db["liked_posts"]
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
        ).decode("utf-8")

    def create_refresh_token(self, subject):
        return jwt.encode(
            {"exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=30), "subject": subject},
            self.key,
        ).decode("utf-8")

    def refresh_token(self, refresh_token):
        subject = jwt.decode(refresh_token.encode("utf-8"), self.key)["subject"]
        return self.create_access_token(subject)

    def decode(self, token):
        return jwt.decode(token.encode("utf-8"), self.key)["subject"]

    #Unused, but helpful.
    def get_token_exp(self, token):
        return str(datetime.datetime.fromtimestamp(jwt.decode(token.encode("utf-8"), self.key)["exp"]))

    def check_token(self, token):
        try:
            jwt.decode(token.encode("utf-8"), self.key)
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.exceptions.DecodeError:
            return False
        except AttributeError:
            return False

    def login_required(self, access_token = Cookie(None)):
        if self.check_token(access_token) == False:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to authorize!")

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

@app.post("/authenticate")
def authenticate(email: str = Body(...), password:str = Body(...)):
    if (user := usersCollection.find_one({"email": email})) != None:
        if bcrypt.checkpw(password.encode(), user["password"]):
            user_obj = {"email": email, "id": str(user["_id"])}
            access_token = jwt_helper.create_access_token(user_obj)
            refresh_token = jwt_helper.create_refresh_token(user_obj)
            response = JSONResponse(content=jsonable_encoder(user_obj), status_code=status.HTTP_200_OK)
            response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=datetime.timedelta(hours=1).total_seconds(), expires=datetime.timedelta(hours=1).total_seconds())
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, max_age=datetime.timedelta(days=30).total_seconds(), expires=datetime.timedelta(days=30).total_seconds())
            return response
            #Authenticated.
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to authenticate!")
            #Failed to authenticate, passwords don't match.
    else:
        #User not found.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Failed to authenticate")

@app.get("/logout")
def logout():
    response = JSONResponse(content=jsonable_encoder({"status": "ok!"}), status_code=status.HTTP_200_OK)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return response

#Refresh route shouldn't be protected
#Because, if the access token is invalid,
#Then the user wouldn't even be able to refresh it.
@app.get("/refresh")
def refresh(refresh_token = Cookie(None)):
    if refresh_token != None:
        try:
            user = jwt_helper.decode(refresh_token)
            new_access_token = jwt_helper.refresh_token(refresh_token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired!")
        response = JSONResponse(content=jsonable_encoder(user), status_code=status.HTTP_200_OK)
        response.set_cookie(key="access_token", value=new_access_token, httponly=True, max_age=datetime.timedelta(hours=1).total_seconds(), expires=datetime.timedelta(hours=1).total_seconds())
        return response
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token!")

@app.get("/users/me", dependencies=[Depends(jwt_helper.login_required)])
def get_current_user(access_token = Cookie(None)):
    current_user = jwt_helper.decode(access_token)
    response = JSONResponse(content=current_user, status_code=status.HTTP_200_OK)
    return response


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

@app.get("/liked_posts/me", dependencies=[Depends(jwt_helper.login_required)])
def liked_posts_me(access_token = Cookie(None)):
    current_user = jwt_helper.decode(access_token)
    liked_posts = list(likedPostsCollection.find({"userId": current_user["id"]}))
    #Getting rid ObjectId, not necessary for the request result.
    for post in liked_posts:
        del post["_id"]
    response = JSONResponse(content=jsonable_encoder({"posts": liked_posts}), status_code=status.HTTP_200_OK)
    return response

@app.post("/like", dependencies=[Depends(jwt_helper.login_required)])
def like_post(post_id: int = Body(embed=True, default=None), access_token = Cookie(None)):
    current_user = jwt_helper.decode(access_token)
    if likedPostsCollection.find_one({"userId": current_user["id"], "postId": post_id}) == None:
        likedPostsCollection.insert_one({"userId": current_user["id"], "postId": post_id})
        response = JSONResponse(content=jsonable_encoder({"status": "ok!"}), status_code=status.HTTP_200_OK)
        return response
    else:
        response = JSONResponse(content=jsonable_encoder({"status": "This user already liked this post!"}), status_code=status.HTTP_400_BAD_REQUEST)
        return response

@app.delete("/dislike", dependencies=[Depends(jwt_helper.login_required)])
def dislike_post(post_id: int = Body(embed=True, default=None), access_token = Cookie(None)):
    current_user = jwt_helper.decode(access_token)
    if (likedPost := likedPostsCollection.find_one({"userId": current_user["id"], "postId": post_id})) != None:
        likedPostsCollection.delete_one(likedPost)
        response = JSONResponse(content=jsonable_encoder({"status": "ok!"}), status_code=status.HTTP_200_OK)
        return response
    else:
        response = JSONResponse(content=jsonable_encoder({"status": "This user has not liked this post!"}), status_code=status.HTTP_400_BAD_REQUEST)
        return response