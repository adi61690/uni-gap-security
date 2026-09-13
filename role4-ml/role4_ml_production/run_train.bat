@echo off
call .venv\Scripts\activate
set PYTHONPATH=src
python scripts\train_all.py
