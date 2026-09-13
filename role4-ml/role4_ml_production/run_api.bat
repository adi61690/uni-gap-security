@echo off
call .venv\Scripts\activate
set PYTHONPATH=src
python -m uvicorn role4_ml.api:app --host 0.0.0.0 --port 8000
