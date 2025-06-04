from fastapi import FastAPI
from app.handlers import test
from app.db.database import create_db_and_tables

app = FastAPI()

@app.on_event("startup")
def startup_event():
    create_db_and_tables()

@app.get("/")
def read_root():
    return {"message": "El Plan API LMAyO en FastAPI funcionando 🎉"}

app.include_router(test.router)