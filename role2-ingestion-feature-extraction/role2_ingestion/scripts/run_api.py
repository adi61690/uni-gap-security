import uvicorn
uvicorn.run('role2_ingest.api:app',host='0.0.0.0',port=int(__import__('os').getenv('ROLE2_API_PORT','8100')),reload=False)
