# GitHub Actions Troubleshooting

## Python fast checks
The dataset generator requires NumPy and pandas. CI installs the pinned versions from `requirements-ci.txt` before running `scripts/build_lab_dataset.py`.

## Frontend
CI uses Node.js 22, installs dependencies with `--legacy-peer-deps`, disables Next telemetry, and runs `npm run build`.

If frontend still fails, open the `frontend` job and copy the first error block rather than the final `exit code 1` summary.
