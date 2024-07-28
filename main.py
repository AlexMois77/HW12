from fastapi import FastAPI
import uvicorn
from src.contacts.routers import router as router_contacts
from src.auth.routers import router as router_auth

app = FastAPI()

app.include_router(router_contacts, prefix="/contacts", tags=["contacts"])
app.include_router(router_auth, prefix="/auth", tags=["auth"])

# @app.get ("api/healthchecker")


def root():
    return {"message": "Welcome to FastApi"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
