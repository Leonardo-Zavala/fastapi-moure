from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

# Entidad user
class User(BaseModel):
    id: int
    name: str
    surname: str
    url: str
    age: int

users_list = [User(id = 1, name = "Leo", surname = "Gunner", url = "https://gnr.com", age = 33),
         User(id = 2, name = "Gunner", surname = "Dev", url = "https://gnrdev.com", age = 32),
         User(id = 3, name = "Haakon", surname = "Dahlberg", url = "https://gnrhaakon.com", age = 38)]

@router.get("/usersjson")
async def usersjson():
    return [{"name":"Leo", "surname": "Gunner", "url": "https://gnr.com", "age": 33},
            {"name":"Gunner", "surname": "Dev", "url": "https://gnrdev.com", "age": 32},
            {"name":"Haakon", "surname": "Dahlberg", "url": "https://gnrhaakon.com", "age": 38}]

@router.get("/users")
async def users():
    return users_list

# Path
@router.get("/user/{id}")
async def user(id: int):
    return search_user(id)

# Query
@router.get("/user/")
async def user(id: int):
    return search_user(id)

@router.post("/user/", response_model=User, status_code=201)
async def user(user: User):
    if type(search_user(user.id)) == User:
        raise HTTPException(status_code=404, detail="El usuario ya existe")
    users_list.append(user)
    return user

@router.put("/user/")
async def user(user: User):
    found = False
    for index, saved_user in enumerate(users_list):
        if saved_user.id == user.id:
            users_list[index] = user
            found = True
    if not found:
        return {"error":"No se ha encontrado el usuario"}
    return user

@router.delete("/user/{id}")
async def user(id: int):
    found = False
    for index, saved_user in enumerate(users_list):
        if saved_user.id == id:
            found = True
            del users_list[index]
    if not found:
        return {"error":"No se ha encontrado el usuario"}
    return {"message":"Usuario eliminado"}
   
def search_user(id: int):
    users = filter(lambda user: user.id == id, users_list)
    try:
        return list(users)[0]
    except:
        return {"error":"No se ha encontrado el usuario"}