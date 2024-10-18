#Fastapi server
from typing import Optional
import base64

import json

import hmac
import hashlib

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "b46676e1fece57e1f4aa45476388cb5b445f95ac96949dd45624bab8dc6335bc"

PASSWORD_SALT = "39d063116c4a2af853c1fb9e2c1e754ee0a7f67d5b15170ac9ac70028add5dd4"



def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_login_from_signed_string(login_signed: str) -> Optional[str]:
    login_base64, sign = login_signed.split(".")
    login = base64.b64decode(login_base64.encode()).decode()
    valid_sign = sign_data(login)
    if hmac.compare_digest(valid_sign,sign):
        return login


def verify_password(login: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[login]["password"].lower()
    return password_hash == stored_password_hash


#Passwords:
#   some_password1
#   some_password2

users = {
    'example_user1@goqle.com': {
        'name': 'Petya',
        'password': '216290c64c9b4696c980a55dd0f25d7ec42ef72cb2d21c438c83d9dad3ebae48',
        'balance': 9_000
    },
    'example_user2@goqle.com': {
        'name': 'Bogdan',
        'password': 'b1bcde8409d671b1482e64a1b593ee0e5ec4d4ea81be090ce81c518cd9a80558',
        'balance': 2_500
    }
}



@app.get("/")
def index_page(login: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not login:
        return Response(login_page, media_type="text/html")
    valid_login = get_login_from_signed_string(login)
    if not valid_login:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="login")
        return response

    try:
        user = users[valid_login]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="login")

        return(response)
    return Response(
        f"Hello, {users[valid_login]['name']}!<br />"
        f"Your balance is {users[valid_login]['balance']}",
        media_type="text/html"
    )


@app.post("/login")
def process_login_page(data = Body(...)):
    data = data.decode("utf-8")
    data = json.loads(data)
    print('data is', data)
    login = data["login"]
    password = data["password"]
    user = users.get(login)

    if not user or not verify_password(login,password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Incorrect data!"
            }),
            media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello {user['name']}!<br />Your balance is {user['balance']}"
            }),
            media_type="application/json")
    
    login_signed = base64.b64encode(login.encode()).decode() + "." + sign_data(login)
    response.set_cookie(key='login', value=login_signed)
    return response
