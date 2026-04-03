from fastapi import FastAPI, UploadFile, File, Request
from contextlib import asynccontextmanager
import os, shutil, tempfile
from backend.pipelines.feature_extraction import extract_all_features
from backend.pipelines.prediction import load_artifacts, run_prediction
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

@asynccontextmanager
async def lifespan(app):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, 'models')
    app.state.artifacts = load_artifacts(models_dir)
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return FileResponse("frontend/templates/dashboard.html")

@app.get('/health')
def health():
    return {"status" : "ok"}

@app.post('/analyze')
async def analyze(request : Request, file : UploadFile = File(...)):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
    try:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_file.close()

        raw_df = extract_all_features(tmp_file.name)

        result = run_prediction(raw_df, request.app.state.artifacts)
    finally:
        os.remove(tmp_file.name)
    return result