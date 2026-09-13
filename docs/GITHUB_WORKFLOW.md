# GitHub workflow

GitHub is used as the source repository and CI validation host. The runtime dashboard still requires the backend/ML services; GitHub Pages is not used for the live system because the project needs a server-side API and WebSocket endpoint.

Every push runs: frontend install/build, Python syntax/unit tests, and dataset reproducibility checks.
