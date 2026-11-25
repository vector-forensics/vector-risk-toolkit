"""Vector (SG) — Grade-Isolated Label Store v1.0 (SQLite WAL, Stdlib Only).

Implements label_spec_v1.md with strict physical & logical isolation across 5 tables:
  - labels_grade_a_official_sanctions : OFAC SDN official texts ONLY
  - labels_grade_b_official_le        : Official Law Enforcement advisories (FBI/DOJ/etc.)
  - labels_grade_c_reference_hubs     : Explorer hubs, bridges, DEX routers, CEX hot wallets
  - labels_grade_d_hypotheses         : Analytical hypotheses & clusters (confidence <= 0.85)
  - labels_quarantine_pending         : Incomplete/unverified records (isolated from lookups)

Plus `dispute_correction_log` for the Phase 1 Appeal & Correction Loop.
"""
from __future__ import annotations

import datetime
import os
import sqlite3
from typing import Any, Dict, List, Optional

GRADE_TABLES = {
    "Grade-A": "labels_grade_a_official_sanctions",
    "Grade-B": "labels_grade_b_official_le",
    "Grade-C": "labels_grade_c_reference_hubs",
    "Grade-D": "labels_grade_d_hypotheses",
}

CASE_SENSITIVE_CHAINS = {"tron", "solana", "bitcoin", "litecoin", "monero", "dash", "zcash", "dogecoin", "bch", "btg", "xvg"}


def norm_address(chain: str, address: str) -> str:
    a = (address or "").strip()
    return a if chain.lower() in CASE_SENSITIVE_CHAINS else a.lower()


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _table_ddl(table_name: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chain TEXT NOT NULL,
        norm_address TEXT NOT NULL,
        address TEXT NOT NULL,
        label TEXT NOT NULL,
        entity TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT 'other',
        source_url TEXT NOT NULL,
        evidence_excerpt TEXT NOT NULL,
        retrieved_at_utc TEXT NOT NULL,
        effective_date_utc TEXT NOT NULL DEFAULT '',
        evidence_grade TEXT NOT NULL,
        confidence REAL NOT NULL,
        reviewer TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        revoked_at_utc TEXT NOT NULL DEFAULT '',
        revocation_source_url TEXT NOT NULL DEFAULT '',
        UNIQUE(chain, norm_address, label, source_url)
    );
    CREATE INDEX IF NOT EXISTS idx_{table_name}_addr ON {table_name}(norm_address);
    CREATE INDEX IF NOT EXISTS idx_{table_name}_chain_addr ON {table_name}(chain, norm_address);
    CREATE INDEX IF NOT EXISTS idx_{table_name}_status ON {table_name}(status);
    """


_QUARANTINE_DDL = """
CREATE TABLE IF NOT EXISTS labels_quarantine_pending (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    raw_address TEXT NOT NULL DEFAULT '',
    raw_chain_or_currency TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    quarantine_reasons TEXT NOT NULL,
    quarantined_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dispute_correction_log (
    appeal_id TEXT PRIMARY KEY,
    evidence_grade TEXT NOT NULL,
    chain TEXT NOT NULL,
    norm_address TEXT NOT NULL,
    label TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    appeal_reason TEXT NOT NULL,
    supporting_url TEXT NOT NULL DEFAULT '',
    appeal_status TEXT NOT NULL DEFAULT 'open',
    resolution_action TEXT NOT NULL DEFAULT '',
    resolution_note TEXT NOT NULL DEFAULT '',
    reviewer TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    resolved_at_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS shadow_mode_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    chain TEXT NOT NULL,
    subject TEXT NOT NULL,
    baseline_verdict TEXT NOT NULL,
    vector_risk_level TEXT NOT NULL,
    vector_score INTEGER NOT NULL,
    lift_category TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
"""


class VectorLabelStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        for tbl in GRADE_TABLES.values():
            self.conn.executescript(_table_ddl(tbl))
        self.conn.executescript(_QUARANTINE_DDL)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for grade, tbl in GRADE_TABLES.items():
            cur = self.conn.execute(f"SELECT COUNT(*) FROM {tbl} WHERE status='active'")
            out[f"{grade}_active"] = cur.fetchone()[0]
            cur_all = self.conn.execute(f"SELECT COUNT(*) FROM {tbl}")
            out[f"{grade}_total"] = cur_all.fetchone()[0]
        out["quarantine"] = self.conn.execute("SELECT COUNT(*) FROM labels_quarantine_pending").fetchone()[0]
        out["appeals"] = self.conn.execute("SELECT COUNT(*) FROM dispute_correction_log").fetchone()[0]
        out["shadow_events"] = self.conn.execute("SELECT COUNT(*) FROM shadow_mode_events").fetchone()[0]
        return out

    def lookup(
        self,
        address: str,
        chain: Optional[str] = None,
        include_disputed: bool = True,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Queries all 4 physically isolated production tables; NEVER reads QUARANTINE."""
        statuses = ("active", "disputed") if include_disputed else ("active",)
        placeholders = ",".join("?" for _ in statuses)
        results: Dict[str, List[Dict[str, Any]]] = {g: [] for g in GRADE_TABLES}

        for grade, tbl in GRADE_TABLES.items():
            if chain:
                na = norm_address(chain, address)
                sql = (
                    f"SELECT * FROM {tbl} WHERE chain=? AND norm_address=? "
                    f"AND status IN ({placeholders}) ORDER BY confidence DESC, id ASC"
                )
                rows = self.conn.execute(sql, (chain.lower(), na, *statuses)).fetchall()
            else:
                # Try both raw (for case-sensitive chains) and lowercased (for EVM)
                a_raw = (address or "").strip()
                a_low = a_raw.lower()
                sql = (
                    f"SELECT * FROM {tbl} WHERE norm_address IN (?, ?) "
                    f"AND status IN ({placeholders}) ORDER BY confidence DESC, id ASC"
                )
                rows = self.conn.execute(sql, (a_raw, a_low, *statuses)).fetchall()
            results[grade] = [dict(r) for r in rows]
        return results

    def submit_appeal(
        self,
        appeal_id: str,
        evidence_grade: str,
        chain: str,
        address: str,
        label: str,
        submitted_by: str,
        appeal_reason: str,
        supporting_url: str = "",
    ) -> Dict[str, Any]:
        if evidence_grade not in ("Grade-C", "Grade-D"):
            raise ValueError("Direct status disputes apply to Grade-C/Grade-D labels; Grade-A/B follow official list revocation.")
        tbl = GRADE_TABLES[evidence_grade]
        na = norm_address(chain, address)
        now = utc_now_iso()
        cur = self.conn.execute(
            f"UPDATE {tbl} SET status='disputed' WHERE chain=? AND norm_address=? AND label=? AND status='active'",
            (chain.lower(), na, label),
        )
        self.conn.execute(
            """
            INSERT OR REPLACE INTO dispute_correction_log
            (appeal_id, evidence_grade, chain, norm_address, label, submitted_by, appeal_reason,
             supporting_url, appeal_status, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (appeal_id, evidence_grade, chain.lower(), na, label, submitted_by, appeal_reason, supporting_url, now),
        )
        self.conn.commit()
        return {
            "appeal_id": appeal_id,
            "appeal_status": "open",
            "labels_marked_disputed": cur.rowcount,
            "created_at_utc": now,
        }

    def resolve_appeal(
        self,
        appeal_id: str,
        resolution_action: str,  # "revoke" | "reinstate"
        reviewer: str,
        resolution_note: str,
        revocation_source_url: str = "",
    ) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM dispute_correction_log WHERE appeal_id=?", (appeal_id,)
        ).fetchone()
        if not row:
            raise KeyError(f"Appeal not found: {appeal_id}")
        if resolution_action not in ("revoke", "reinstate"):
            raise ValueError("resolution_action must be 'revoke' or 'reinstate'")

        tbl = GRADE_TABLES[row["evidence_grade"]]
        now = utc_now_iso()
        new_status = "revoked" if resolution_action == "revoke" else "active"
        if new_status == "revoked":
            cur = self.conn.execute(
                f"UPDATE {tbl} SET status='revoked', revoked_at_utc=?, revocation_source_url=? "
                f"WHERE chain=? AND norm_address=? AND label=?",
                (now, revocation_source_url or f"internal://appeal/{appeal_id}", row["chain"], row["norm_address"], row["label"]),
            )
        else:
            cur = self.conn.execute(
                f"UPDATE {tbl} SET status='active' WHERE chain=? AND norm_address=? AND label=?",
                (row["chain"], row["norm_address"], row["label"]),
            )
        self.conn.execute(
            """
            UPDATE dispute_correction_log
            SET appeal_status='resolved', resolution_action=?, resolution_note=?, reviewer=?, resolved_at_utc=?
            WHERE appeal_id=?
            """,
            (resolution_action, resolution_note, reviewer, now, appeal_id),
        )
        self.conn.commit()
        return {
            "appeal_id": appeal_id,
            "appeal_status": "resolved",
            "resolution_action": resolution_action,
            "new_label_status": new_status,
            "rows_updated": cur.rowcount,
            "resolved_at_utc": now,
        }

    def list_appeals(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM dispute_correction_log ORDER BY created_at_utc DESC").fetchall()
        return [dict(r) for r in rows]

    def log_shadow_event(
        self,
        event_id: str,
        client_id: str,
        chain: str,
        subject: str,
        baseline_verdict: str,
        vector_risk_level: str,
        vector_score: int,
        lift_category: str,
        evidence_hash: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO shadow_mode_events
            (event_id, client_id, chain, subject, baseline_verdict, vector_risk_level,
             vector_score, lift_category, evidence_hash, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, client_id, chain.lower(), subject, baseline_verdict, vector_risk_level,
             int(vector_score), lift_category, evidence_hash, utc_now_iso()),
        )
        self.conn.commit()

    def shadow_summary(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        if client_id:
            rows = self.conn.execute("SELECT * FROM shadow_mode_events WHERE client_id=?", (client_id,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM shadow_mode_events").fetchall()
        by_lift: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        for r in rows:
            by_lift[r["lift_category"]] = by_lift.get(r["lift_category"], 0) + 1
            by_level[r["vector_risk_level"]] = by_level.get(r["vector_risk_level"], 0) + 1
        return {
            "total_shadow_events": len(rows),
            "client_filter": client_id or "ALL",
            "by_lift_category": by_lift,
            "by_vector_risk_level": by_level,
        }
