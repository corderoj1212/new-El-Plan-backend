from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "El Plan API LMAyO en FastAPI funcionando 🎉"}

@app.post