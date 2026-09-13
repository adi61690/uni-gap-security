@echo off
call .venv\Scripts\activate
set PYTHONPATH=src
python -c "import json; from role4_ml.detector import Role4Detector; from role4_ml.schemas import PredictRequest; d=Role4Detector(); print(d.predict(PredictRequest(**json.load(open('examples/dns_event.json')))).model_dump_json(indent=2))"
