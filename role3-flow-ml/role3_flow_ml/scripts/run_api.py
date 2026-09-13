import sys, uvicorn
sys.path.insert(0,'src')
from role3_ml.api import app
uvicorn.run(app,host='0.0.0.0',port=8002)
