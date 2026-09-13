from pathlib import Path
import py_compile
import sys

ROOT = Path(__file__).resolve().parents[1]
roots = [
    ROOT / 'backend',
    ROOT / 'role1-network-traffic-simulation',
    ROOT / 'role2-ingestion-feature-extraction',
    ROOT / 'role3-flow-ml',
    ROOT / 'role4-ml',
]
errors = []
for base in roots:
    for path in base.rglob('*.py'):
        if any(part in {'.venv','__pycache__','.pytest_cache'} for part in path.parts):
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            errors.append(f'{path}: {exc}')
if errors:
    print('Python syntax check failed:')
    print('\n'.join(errors))
    sys.exit(1)
print('Python syntax check passed for project services.')
