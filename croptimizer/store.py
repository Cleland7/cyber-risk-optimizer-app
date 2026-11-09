"""Snapshot storage (SQLite for replay mode; the same schema ports to PostgreSQL).
Every metric row carries a `source` column: Measured (from Wazuh) or Declared (manual input)."""
import json, sqlite3, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_snapshots(
  id INTEGER PRIMARY KEY, label TEXT, taken_at TEXT, assumptions_version TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS snapshot_metrics(
  snapshot_id INTEGER, metric TEXT, value REAL, source TEXT CHECK(source IN ('Measured','Declared')));
"""


def save_snapshot(path, label, assumptions_version, metrics, detail):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    cur = con.execute("INSERT INTO risk_snapshots(label,taken_at,assumptions_version,detail) VALUES(?,?,?,?)",
                      (label, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), assumptions_version, json.dumps(detail)))
    sid = cur.lastrowid
    con.executemany("INSERT INTO snapshot_metrics VALUES(?,?,?,?)", [(sid, m, v, s) for m, v, s in metrics])
    con.commit(); con.close()
    return sid
