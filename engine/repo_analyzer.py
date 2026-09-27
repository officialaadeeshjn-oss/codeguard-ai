"""
engine/repo_analyzer.py
-----------------------
Lightweight repository analyzer for CodeGuard AI.

Scans a repository root directory and identifies well-known components
(entry points, auth middleware, routes, models, tests, deployment config).
It only reports components that actually exist on disk — it never invents
paths or assumes every component is present.

Usage:
    from engine.repo_analyzer import analyze_repo
    info = analyze_repo("/path/to/repo")
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Component signatures
# Each entry is (label, list-of-candidate-relative-paths-or-glob-names).
# The analyzer walks the repo and matches on filename or path substring.
# ---------------------------------------------------------------------------

_SIGNATURES = {
    "frontend_entry": [
        "frontend/index.html", "frontend/src/index.js", "frontend/src/main.js",
        "frontend/src/App.jsx", "frontend/src/App.tsx", "src/index.js",
        "src/main.js", "public/index.html",
    ],
    "backend_entry": [
        "app.py", "main.py", "server.py", "index.js", "src/index.js",
        "src/app.js", "src/server.js", "api/index.js", "api/app.py",
        "api/main.py", "wsgi.py", "manage.py",
    ],
    "auth_middleware": [
        "middleware/auth.js", "middleware/auth.py", "middleware/authenticate.js",
        "auth/middleware.py", "auth/middleware.js", "src/middleware/auth.js",
        "src/middleware/auth.py",
    ],
    "auth_routes": [
        "routes/auth.js", "routes/auth.py", "api/auth.js", "api/auth.py",
        "src/routes/auth.js", "auth/routes.py", "auth/views.py",
        "controllers/auth.js", "controllers/auth.py",
    ],
    "user_model": [
        "models/user.js", "models/user.py", "models/User.js", "models/User.py",
        "src/models/user.js", "schemas/user.py", "db/user.py",
        "database/models/user.py",
    ],
    "password_reset_service": [
        "services/reset.js", "services/reset.py", "services/passwordReset.js",
        "services/otp.py", "services/otp.js", "auth/reset.py", "auth/otp.py",
        "utils/reset.py", "utils/otp.py",
    ],
    "test_directory": [
        "tests/", "test/", "__tests__/", "spec/",
    ],
    "test_files": [
        # matched by filename prefix/suffix, not exact path
    ],
    "deployment_config": [
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".github/workflows", "deploy.sh", "k8s/", "kubernetes/",
        "Procfile", "fly.toml", "render.yaml", "heroku.yml",
        ".travis.yml", "appspec.yml",
    ],
}

# File-name patterns that identify test files (checked across all .py/.js)
_TEST_FILE_PATTERNS = ("test_", "_test.py", ".test.js", ".spec.js", ".test.ts",
                       ".spec.ts", "spec.js")


def _find_existing(root: Path, candidates: list) -> list:
    """Return the subset of candidate relative paths that exist under root."""
    found = []
    for c in candidates:
        p = root / c
        if p.exists():
            found.append(str(Path(c)))  # normalised separators
    return found


def _find_test_files(root: Path) -> list:
    """Walk the tree and collect files whose names look like test files."""
    found = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip hidden dirs and __pycache__
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d != "__pycache__"]
            for fname in filenames:
                if any(fname.startswith(p) or fname.endswith(p)
                       for p in _TEST_FILE_PATTERNS):
                    rel = Path(dirpath).relative_to(root) / fname
                    found.append(str(rel))
    except Exception:
        pass
    return found


def analyze_repo(root=None) -> dict:
    """
    Scan the repository at *root* (defaults to the project root inferred from
    this file's location) and return a structured dict describing the
    components found.

    Returns
    -------
    dict with keys:
        root          – absolute path scanned
        components    – dict mapping component label → list of found paths
        summary       – human-readable list of one-line findings
        missing       – list of component labels not found
    """
    if root is None:
        # Default: two levels up from engine/repo_analyzer.py
        root = Path(__file__).parent.parent

    root = Path(root).resolve()

    components = {}

    for label, candidates in _SIGNATURES.items():
        if label == "test_files":
            # handled separately below
            continue
        if label == "test_directory":
            components[label] = _find_existing(root, candidates)
        else:
            components[label] = _find_existing(root, candidates)

    # Test files: full walk
    components["test_files"] = _find_test_files(root)

    # Build human-readable summary
    summary = []
    missing = []
    for label, paths in components.items():
        if paths:
            summary.append(f"{label}: {', '.join(paths)}")
        else:
            missing.append(label)

    return {
        "root": str(root),
        "components": components,
        "summary": summary,
        "missing": missing,
    }


if __name__ == "__main__":
    import json
    result = analyze_repo()
    print(json.dumps(result, indent=2))
