from fastapi import FastAPI

app = FastAPI(title="Aletheia Threat Intelligence Platform")


@app.get("/health")
def health():
    return {"status": "ok"}
