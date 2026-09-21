"""Single-worker, durable security state for the supported production profile."""
import asyncio
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from interceptor.taint import TaintEngine, TaintLevel


class DurableState:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS tainted (scope TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS quarantine (tool TEXT PRIMARY KEY)")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def contains(self, scope):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM tainted WHERE scope=?", (scope,)).fetchone() is not None

    def mark(self, scope):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO tainted VALUES (?)", (scope,))

    def quarantine(self, tool):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO quarantine VALUES (?)", (tool,))

    def quarantined(self):
        with self.connect() as db:
            return {row[0] for row in db.execute("SELECT tool FROM quarantine")}


class DurableTaintEngine(TaintEngine):
    """Coarse marks never expire automatically or depend on Redis survival.

    A new conversation needs a fresh trusted IdP session claim. The supported
    deployment has one process, which serializes decisions before forwarding.
    """
    def __init__(self, cfg, state, redis_client=None):
        if cfg.taint_mode != "coarse":
            raise ValueError("Durable production policy requires coarse taint mode")
        super().__init__(cfg, redis_client)
        self.state = state
        self._decision_lock = asyncio.Lock()

    def get_lock(self, session_id):
        return self._decision_lock

    async def get_level(self, session_id):
        return TaintLevel.TAINTED if self.state.contains(session_id) else TaintLevel.CLEAN

    async def mark_tainted(self, session_id):
        self.state.mark(session_id)

    async def untaint(self, session_id):
        raise RuntimeError("Production taint cannot be cleared through the runtime API")


class SingleWorkerLock:
    """Lifetime process lock on the data directory; acquired during startup."""
    def __init__(self, directory):
        self.path = Path(directory) / "gateway.lock"
        self.file = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+b")
        try:
            if __import__("os").name == "nt":
                import msvcrt
                self.file.seek(0)
                if self.file.read(1) == b"":
                    self.file.write(b"0"); self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            self.file.close(); self.file = None
            raise RuntimeError("Data directory already owned by another gateway worker")

    def close(self):
        if self.file:
            self.file.close(); self.file = None
