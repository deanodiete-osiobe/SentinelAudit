"""Append-only application ledger. Remote retention is needed to detect rollback.

SQLite serializes writers; each record commits before being made available for
upload. Hashes cover sequence, previous digest and canonical JSON payload.
This is tamper evidence, not protection against a privileged local attacker.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

ZERO = "0" * 64

def digest(seq, previous, payload):
    return hashlib.sha256(f"{seq}\n{previous}\n{payload}".encode("utf-8")).hexdigest()

class Ledger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        from contextlib import closing
        with closing(self.connect()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS receipt(id INTEGER PRIMARY KEY CHECK(id=1), seq INTEGER NOT NULL)")
            db.commit()
        self.verify()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def verify(self):
        previous, sequence = ZERO, 0
        db = self.connect()
        try:
            for seq, prev, payload, hashed in db.execute("SELECT seq, previous, payload, hash FROM ledger ORDER BY seq"):
                if seq != sequence + 1 or prev != previous or digest(seq, prev, payload) != hashed:
                    raise ValueError("CRITICAL: local audit ledger integrity failure")
                previous, sequence = hashed, seq
            receipt = db.execute("SELECT seq FROM receipt WHERE id=1").fetchone()
            if receipt and receipt[0] > sequence:
                raise ValueError("CRITICAL: audit ledger truncated behind retained receipt")
            return sequence, previous
        finally:
            db.close()

    def append(self, event):
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(payload.encode()) > 262144:
            raise ValueError("Ledger record exceeds 256 KiB")
        if self.path.stat().st_size > 256 * 1024 * 1024:
            raise RuntimeError("Ledger capacity reached; archive under administrator control")
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            last = db.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (1, ZERO)
            db.execute("INSERT INTO ledger VALUES(?,?,?,?)", (seq, prev, payload, digest(seq, prev, payload)))
            db.commit()
            return seq
        finally:
            db.close()

    def pending(self, limit=20):
        db = self.connect()
        try:
            receipt = db.execute("SELECT seq FROM receipt WHERE id=1").fetchone()
            rows = db.execute("SELECT seq, previous, payload, hash FROM ledger WHERE seq>? ORDER BY seq LIMIT ?", (receipt[0] if receipt else 0, min(limit,20))).fetchall()
            batch, size = [], 0
            for row in rows:
                item = dict(zip(("seq","previous","payload","hash"), row))
                size += len(json.dumps(item).encode())
                if size > 1024*1024: break
                batch.append(item)
            return batch
        finally:
            db.close()

    def acknowledge(self, seq, hashed):
        db = self.connect()
        try:
            with db:
                row = db.execute("SELECT hash FROM ledger WHERE seq=?", (seq,)).fetchone()
                if not row or row[0] != hashed:
                    raise ValueError("Remote ledger receipt does not match local history")
                db.execute("INSERT INTO receipt VALUES(1,?) ON CONFLICT(id) DO UPDATE SET seq=max(seq,excluded.seq)", (seq,))
        finally:
            db.close()


def activity_directory():
    import os
    root = Path(os.environ.get('LOCALAPPDATA') or Path.home()/'.local'/'share')/'SentinelAudit'
    root.mkdir(parents=True,exist_ok=True)
    if os.name != 'nt': root.chmod(0o700)
    return root


def record_export(action):
    """Record every export outcome; never confuse successful save with log failure."""
    import functools
    import hashlib
    def decorate(method):
        @functools.wraps(method)
        def wrapped(self,*args,**kwargs):
            try:
                self._activity(action+'_requested')
            except Exception:
                return {'saved_to':None,'error':'Audit trail is unavailable or has failed integrity verification. Preserve the ledger and restore from a trusted backup before exporting.'}
            try:
                result=method(self,*args,**kwargs)
            except Exception as exc:
                result={'saved_to':None,'error':f'Export failed ({type(exc).__name__}). Check destination permissions and free disk space, then retry.'}
            saved=result.get('saved_to')
            outcome='completed' if saved else 'failed' if result.get('error') else 'cancelled'
            details={}
            try:
                if saved:
                    hashed=hashlib.sha256()
                    with open(saved,'rb') as source:
                        for chunk in iter(lambda:source.read(65536),b''):hashed.update(chunk)
                    details={'filename':Path(saved).name,'sha256':hashed.hexdigest()}
                self._activity(action+'_'+outcome,**details)
            except Exception:
                result['warning']='The export outcome could not be recorded in the audit trail. Preserve the local ledger for investigation.'
            return result
        return wrapped
    return decorate


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Verify the local SentinelAudit activity chain without modifying records.')
    parser.add_argument('--path',type=Path,default=activity_directory()/'activity-ledger.sqlite3')
    args=parser.parse_args()
    if not args.path.is_file():parser.error('No activity ledger exists at this path')
    ledger=object.__new__(Ledger);ledger.path=args.path
    sequence,head=ledger.verify()
    print(f'Verified {sequence} records. Head SHA-256: {head}')
