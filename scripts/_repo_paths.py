import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
NODES_DIR = REPO_ROOT / "nodes"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
# 快照/中间产物只写缓存目录, 不进仓库 (CI 每次全新 runner, 缓存无意义)。
if sys.platform == "darwin":
    _cache_base = Path.home() / "Library" / "Caches"
elif os.name == "nt":
    _cache_base = Path.home() / "AppData" / "Local" / "Temp"
else:
    _cache_base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
CACHE_DIR = _cache_base / "airport-mining"
NODES_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)
