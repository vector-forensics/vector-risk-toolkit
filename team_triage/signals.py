"""Vector (SG) — 18 Public GitHub API & On-Chain Risk-Triage Signals (6 Families).

Matches `track_b_team_triage_brief_v0.1.md` 1:1 with strict privacy & honesty guardrails:
  - PROHIBITED: nationality, language, geolocation guesses, ethnic-name classifiers.
  - PII REDACTION: commit/profile emails are immediately scrubbed to (domain, sha256_prefix).
  - SEPARATION: every output separates OBSERVED FACTS, ANALYTICAL SIGNALS (each paired with a
    Benign Counter-Hypothesis), and UNCONFIRMED GAPS + VERIFICATION CHECKLIST.
  - ON-CHAIN: exact-match screening against VectorLabelStore (Grade-A OFAC SDN + Grade-C hubs).
"""
from __future__ import annotations

from collections import Counter, defaultdict
import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from risk_api.engine import VectorRiskEngine
from . import TRIAGE_ENGINE_VERSION

# Public major open-source repos explicitly excluded from "niche overlap" (SIG-14)
# to prevent false merges on legitimate ecosystem contributors.
MAJOR_PUBLIC_OSS_REPOS = {
    "ethereum/go-ethereum",
    "foundry-rs/foundry",
    "openzeppelin/openzeppelin-contracts",
    "bnb-chain/bsc",
    "paradigmxyz/reth",
    "bitcoin/bitcoin",
    "solana-labs/solana",
    "uniswap/v3-core",
    "uniswap/v4-core",
    "pancakeswap/pancake-frontend",
    "pancakeswap/pancake-smart-contracts",
    "aave/aave-v3-core",
    "torvalds/linux",
}

PRIVACY_OR_DISPOSABLE_DOMAINS = {
    "proton.me",
    "protonmail.com",
    "tutanota.com",
    "tuta.io",
    "guerrillamail.com",
    "mailinator.com",
    "10minutemail.com",
    "temp-mail.org",
    "cock.li",
    "sharklasers.com",
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "recent_account_days": 90,
    "burst_creation_window_hours": 72,
    "dormant_tenure_days": 180,
    "dormant_max_prior_repos": 2,
    "dormant_recent_commit_threshold": 15,
    "bulk_seed_commit_share": 0.80,
    "bulk_seed_min_lines": 500,
    "privacy_domain_ratio": 0.50,
    "sync_commit_window_seconds": 120,
    "sync_commit_min_pairs": 2,
    "utc_shift_min_hours": 4,
    "fast_pr_approval_seconds": 300,
    "inorganic_star_min": 50,
}

EVM_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRON_ADDR_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")

PROHIBITED_FEATURE_AUDIT = {
    "uses_nationality": False,
    "uses_language_detection": False,
    "uses_ethnic_name_heuristics": False,
    "uses_ip_or_geolocation": False,
    "emits_raw_emails": False,
    "is_dprk_identity_detector": False,
}


def scrub_email(raw_email: Optional[str]) -> Dict[str, str]:
    """Never emit raw PII emails. Returns strictly domain + sha256 prefix."""
    e = (raw_email or "").strip().lower()
    if not e or "@" not in e:
        return {"email_hash": "none", "email_domain": "unknown"}
    domain = e.split("@", 1)[1]
    h = hashlib.sha256(e.encode("utf-8")).hexdigest()[:16]
    return {"email_hash": f"sha256:{h}", "email_domain": domain}


def parse_iso_utc(ts: Optional[str]) -> Optional[datetime.datetime]:
    if not ts:
        return None
    s = ts.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def extract_utc_offset_hours(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    s = ts.strip()
    if s.endswith("Z"):
        return 0.0
    m = re.search(r"([+-])(\d{2}):?(\d{2})$", s)
    if not m:
        return None
    sign = 1.0 if m.group(1) == "+" else -1.0
    return sign * (int(m.group(2)) + int(m.group(3)) / 60.0)


def canonical_sha256(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def evaluate_triage_snapshot(
    snapshot: Dict[str, Any],
    label_db_path: str,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate all 18 public signals across 6 families on a frozen snapshot."""
    cfg = dict(DEFAULT_CONFIG)
    if config:
        cfg.update(config)

    snap_time = parse_iso_utc(snapshot.get("snapshot_utc")) or datetime.datetime.now(datetime.timezone.utc)
    contributors = snapshot.get("contributors", [])
    repos = snapshot.get("repos", [])
    commits = snapshot.get("commits", [])
    pull_requests = snapshot.get("pull_requests", [])
    declared_addresses = snapshot.get("declared_addresses", [])

    # Scrub any raw email fields in memory immediately so downstream code cannot leak them
    scrubbed_commits: List[Dict[str, Any]] = []
    for c in commits:
        ae = scrub_email(c.get("author_email"))
        ce = scrub_email(c.get("committer_email"))
        if c.get("author_email_hash"):
            ae = {"email_hash": c["author_email_hash"], "email_domain": c.get("author_email_domain", "unknown")}
        if c.get("committer_email_hash"):
            ce = {"email_hash": c["committer_email_hash"], "email_domain": c.get("committer_email_domain", "unknown")}
        sc = {
            "repo": c.get("repo", ""),
            "sha": c.get("sha", ""),
            "url": c.get("url", ""),
            "author_login": (c.get("author_login") or "").lower(),
            "committer_login": (c.get("committer_login") or "").lower(),
            "author_email_hash": ae["email_hash"],
            "author_email_domain": ae["email_domain"],
            "committer_email_hash": ce["email_hash"],
            "committer_email_domain": ce["email_domain"],
            "timestamp": c.get("timestamp", ""),
            "verified": bool(c.get("verified", False)),
            "additions": int(c.get("additions", 0)),
            "deletions": int(c.get("deletions", 0)),
            "message": c.get("message", ""),
        }
        scrubbed_commits.append(sc)

    observed_facts: List[Dict[str, Any]] = []
    signals_eval: List[Dict[str, Any]] = []

    def record_signal(
        sig_id: str,
        family: str,
        name: str,
        triggered: bool,
        severity: str,
        weight: int,
        confidence: float,
        evidence: str,
        evidence_urls: List[str],
        benign_counter_hypothesis: str,
    ) -> None:
        signals_eval.append({
            "signal_id": sig_id,
            "family": family,
            "name": name,
            "triggered": triggered,
            "severity": severity if triggered else "NONE",
            "weight": weight if triggered else 0,
            "confidence": round(confidence, 2),
            "evidence": evidence,
            "evidence_urls": evidence_urls[:8],
            "benign_counter_hypothesis": benign_counter_hypothesis,
        })

    # --- Family 1: Account Lifecycle & Tenure (SIG-01..SIG-03) ---
    recent_accounts = []
    created_times: List[Tuple[str, datetime.datetime, str]] = []
    dormant_burst = []
    commits_by_login = Counter(c["author_login"] for c in scrubbed_commits if c["author_login"])

    for u in contributors:
        login = (u.get("login") or "").lower()
        dt = parse_iso_utc(u.get("created_at"))
        url = u.get("html_url") or f"https://github.com/{login}"
        if dt:
            age_days = (snap_time - dt).days
            created_times.append((login, dt, url))
            if age_days < cfg["recent_account_days"]:
                recent_accounts.append((login, age_days, url))
            if (
                age_days >= cfg["dormant_tenure_days"]
                and int(u.get("public_repos", 0)) <= cfg["dormant_max_prior_repos"]
                and commits_by_login.get(login, 0) >= cfg["dormant_recent_commit_threshold"]
            ):
                dormant_burst.append((login, age_days, commits_by_login[login], url))

    record_signal(
        "SIG-01", "1. Account Lifecycle & Tenure", "Account Creation Recency",
        triggered=len(recent_accounts) > 0,
        severity="MEDIUM", weight=10, confidence=0.75,
        evidence=(
            f"{len(recent_accounts)}/{len(contributors)} contributor account(s) created <{cfg['recent_account_days']}d before snapshot: "
            + ", ".join(f"{x[0]} ({x[1]}d)" for x in recent_accounts)
            if recent_accounts else f"0/{len(contributors)} accounts created <{cfg['recent_account_days']}d before snapshot."
        ),
        evidence_urls=[x[2] for x in recent_accounts],
        benign_counter_hypothesis="Engineers switching from private corporate GitLab/Bitbucket or opening fresh work-specific GitHub accounts for a new startup.",
    )

    burst_pairs = []
    created_times.sort(key=lambda x: x[1])
    for i in range(len(created_times)):
        for j in range(i + 1, len(created_times)):
            delta_h = abs((created_times[j][1] - created_times[i][1]).total_seconds()) / 3600.0
            if delta_h <= cfg["burst_creation_window_hours"]:
                burst_pairs.append((created_times[i][0], created_times[j][0], round(delta_h, 1), created_times[i][2], created_times[j][2]))

    record_signal(
        "SIG-02", "1. Account Lifecycle & Tenure", "Synchronized Burst-Creation Cluster",
        triggered=len(burst_pairs) > 0,
        severity="MEDIUM", weight=14, confidence=0.78,
        evidence=(
            f"{len(burst_pairs)} contributor pair(s) created within {cfg['burst_creation_window_hours']}h: "
            + "; ".join(f"{a} & {b} ({h}h apart)" for a, b, h, _, _ in burst_pairs[:4])
            if burst_pairs else "No synchronized account creation clusters detected."
        ),
        evidence_urls=list({u for p in burst_pairs for u in (p[3], p[4])}),
        benign_counter_hypothesis="Founding cohort onboarding together during a hackathon or company GitHub Enterprise setup.",
    )

    record_signal(
        "SIG-03", "1. Account Lifecycle & Tenure", "Dormant-to-High-Velocity Reactivation",
        triggered=len(dormant_burst) > 0,
        severity="LOW", weight=8, confidence=0.65,
        evidence=(
            f"{len(dormant_burst)} older low-footprint account(s) showed sudden high commit velocity: "
            + ", ".join(f"{l} ({d}d old, {cnt} commits)" for l, d, cnt, _ in dormant_burst)
            if dormant_burst else "No dormant-account sudden reactivation anomalies observed."
        ),
        evidence_urls=[x[3] for x in dormant_burst],
        benign_counter_hypothesis="Senior developer whose prior work lived in private enterprise repos before joining a public open-source project.",
    )

    # --- Family 2: Commit & Authorship Hygiene (SIG-04..SIG-07) ---
    mismatch_commits = []
    for c in scrubbed_commits:
        if (
            c["author_email_hash"] != "none"
            and c["committer_email_hash"] != "none"
            and c["author_email_hash"] != c["committer_email_hash"]
            and c["committer_email_domain"] != "users.noreply.github.com"
            and c["committer_login"] != "web-flow"
        ):
            mismatch_commits.append(c)

    record_signal(
        "SIG-04", "2. Commit & Authorship Hygiene", "Author / Committer Mismatch Anomaly",
        triggered=len(mismatch_commits) >= 2,
        severity="MEDIUM", weight=12, confidence=0.74,
        evidence=(
            f"{len(mismatch_commits)} commit(s) show non-web-flow author/committer email hash mismatch "
            f"(e.g., author {mismatch_commits[0]['author_email_hash']} vs committer {mismatch_commits[0]['committer_email_hash']})."
            if len(mismatch_commits) >= 2 else f"{len(mismatch_commits)} non-web-flow author/committer mismatch commit(s) (below threshold)."
        ),
        evidence_urls=[c["url"] for c in mismatch_commits if c["url"]],
        benign_counter_hypothesis="Maintainer rebasing/cherry-picking PRs locally or migrating commits from a private repo on one build machine.",
    )

    bulk_repos = []
    commits_by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in scrubbed_commits:
        commits_by_repo[c["repo"]].append(c)
    for rname, rcommits in commits_by_repo.items():
        total_add = sum(c["additions"] for c in rcommits)
        if total_add >= cfg["bulk_seed_min_lines"] and rcommits:
            top_c = max(rcommits, key=lambda x: x["additions"])
            share = top_c["additions"] / float(total_add)
            if share >= cfg["bulk_seed_commit_share"]:
                bulk_repos.append((rname, round(share * 100, 1), top_c["additions"], top_c["url"]))

    record_signal(
        "SIG-05", "2. Commit & Authorship Hygiene", "Bulk Single-Commit Repo Seeding",
        triggered=len(bulk_repos) > 0,
        severity="MEDIUM", weight=12, confidence=0.72,
        evidence=(
            f"{len(bulk_repos)} repo(s) seeded via a single bulk commit (>={int(cfg['bulk_seed_commit_share']*100)}% LOC): "
            + ", ".join(f"{r} ({pct}%, {loc} LOC)" for r, pct, loc, _ in bulk_repos)
            if bulk_repos else "No single-commit bulk repo dumps detected."
        ),
        evidence_urls=[x[3] for x in bulk_repos if x[3]],
        benign_counter_hypothesis="Legitimate protocol squashing commit history before open-sourcing audited contracts prior to launch.",
    )

    unique_email_entries = {}
    for c in scrubbed_commits:
        if c["author_email_hash"] != "none":
            unique_email_entries[c["author_email_hash"]] = c["author_email_domain"]
    priv_emails = [h for h, dom in unique_email_entries.items() if dom in PRIVACY_OR_DISPOSABLE_DOMAINS]
    priv_ratio = (len(priv_emails) / float(len(unique_email_entries))) if unique_email_entries else 0.0

    record_signal(
        "SIG-06", "2. Commit & Authorship Hygiene", "Privacy / Disposable Email Domain Concentration",
        triggered=len(unique_email_entries) > 0 and priv_ratio >= cfg["privacy_domain_ratio"],
        severity="LOW", weight=6, confidence=0.60,
        evidence=(
            f"{len(priv_emails)}/{len(unique_email_entries)} distinct commit email hashes use privacy/disposable domains "
            f"(domains: {sorted({unique_email_entries[h] for h in priv_emails})}; raw addresses redacted)."
            if unique_email_entries else "No commit author email domains available in snapshot."
        ),
        evidence_urls=[],
        benign_counter_hypothesis="Security-conscious Web3 builders routinely use ProtonMail or privacy email providers for personal OPSEC.",
    )

    verified_count = sum(1 for c in scrubbed_commits if c["verified"])
    verified_ratio = (verified_count / float(len(scrubbed_commits))) if scrubbed_commits else 0.0
    record_signal(
        "SIG-07", "2. Commit & Authorship Hygiene", "Commit Cryptographic Signature (GPG/SSH) Hygiene",
        triggered=len(scrubbed_commits) >= 5 and verified_ratio == 0.0,
        severity="LOW", weight=5, confidence=0.68,
        evidence=f"{verified_count}/{len(scrubbed_commits)} analyzed commits carry GitHub-verified GPG/SSH signatures ({verified_ratio*100:.1f}%).",
        evidence_urls=[],
        benign_counter_hypothesis="Many legitimate developers do not configure GPG/SSH commit signing in local Git clients.",
    )

    # --- Family 3: Temporal Activity Patterns (SIG-08..SIG-10) ---
    dated_commits = []
    for c in scrubbed_commits:
        dt = parse_iso_utc(c["timestamp"])
        if dt:
            dated_commits.append((dt, c))
    dated_commits.sort(key=lambda x: x[0])

    sync_events = []
    for i in range(len(dated_commits) - 1):
        dt1, c1 = dated_commits[i]
        dt2, c2 = dated_commits[i + 1]
        if c1["author_login"] and c2["author_login"] and c1["author_login"] != c2["author_login"]:
            gap_s = (dt2 - dt1).total_seconds()
            if 0 <= gap_s <= cfg["sync_commit_window_seconds"]:
                sync_events.append((c1["author_login"], c2["author_login"], int(gap_s), c1["url"], c2["url"]))

    record_signal(
        "SIG-08", "3. Temporal Activity Patterns", "Synchronized Multi-Account Commit Cadence",
        triggered=len(sync_events) >= cfg["sync_commit_min_pairs"],
        severity="MEDIUM", weight=10, confidence=0.66,
        evidence=(
            f"{len(sync_events)} cross-account commit pair(s) landed within {cfg['sync_commit_window_seconds']}s of each other."
            if sync_events else "No abnormal cross-account rapid commit clustering detected."
        ),
        evidence_urls=list({u for e in sync_events for u in (e[3], e[4]) if u}),
        benign_counter_hypothesis="Pair programming, simultaneous PR merges by CI merge queue, or active release day collaboration.",
    )

    offsets_by_login: Dict[str, List[float]] = defaultdict(list)
    for c in scrubbed_commits:
        off = extract_utc_offset_hours(c["timestamp"])
        if off is not None and c["author_login"]:
            offsets_by_login[c["author_login"]].append(off)
    offset_shifts = []
    for login, offs in offsets_by_login.items():
        if len(set(offs)) >= 2:
            span = max(offs) - min(offs)
            if span >= cfg["utc_shift_min_hours"]:
                offset_shifts.append((login, min(offs), max(offs), span))

    record_signal(
        "SIG-09", "3. Temporal Activity Patterns", "Abrupt UTC Offset Shifts (Coarse Signal Only)",
        triggered=len(offset_shifts) > 0,
        severity="LOW", weight=6, confidence=0.52,
        evidence=(
            f"{len(offset_shifts)} contributor(s) exhibited >={cfg['utc_shift_min_hours']}h UTC offset shifts in commit timestamps: "
            + ", ".join(f"{l} (UTC{mn:+.1f} to UTC{mx:+.1f})" for l, mn, mx, _ in offset_shifts)
            if offset_shifts else "No large UTC offset discontinuities detected."
        ),
        evidence_urls=[],
        benign_counter_hypothesis="Coarse signal only: remote travel, cloud IDE/Codespaces (UTC+0), VPN/VM timezone defaults, or GitHub web merges fully explain offset changes.",
    )

    hour_buckets = Counter(dt.hour for dt, _ in dated_commits)
    narrow_band = False
    if len(dated_commits) >= 10:
        top3_share = sum(v for _, v in hour_buckets.most_common(3)) / float(len(dated_commits))
        if top3_share >= 0.85:
            narrow_band = True
    record_signal(
        "SIG-10", "3. Temporal Activity Patterns", "Narrow-Band / Batch Commit Schedule Discontinuity",
        triggered=narrow_band,
        severity="LOW", weight=5, confidence=0.50,
        evidence=(
            f">=85% of {len(dated_commits)} commits fell into just 3 UTC hours (batch/automated push cadence)."
            if narrow_band else f"Commit timestamps across {len(dated_commits)} commits show normal multi-hour spread."
        ),
        evidence_urls=[],
        benign_counter_hypothesis="Part-time developer pushing once daily after day job, or scheduled CI mirror pushing daily snapshots.",
    )

    # --- Family 4: Repository & Fork Provenance (SIG-11..SIG-13) ---
    rebranded_forks = [
        r for r in repos
        if r.get("is_fork") and int(r.get("original_commits_ahead", 99)) <= 3
    ]
    record_signal(
        "SIG-11", "4. Repository & Fork Provenance", "Forked-then-Rebranded Minimal-Delta Repo",
        triggered=len(rebranded_forks) > 0,
        severity="MEDIUM", weight=11, confidence=0.74,
        evidence=(
            f"{len(rebranded_forks)} repo(s) are forks with <=3 original commits ahead of upstream: "
            + ", ".join(r.get("full_name", "") for r in rebranded_forks)
            if rebranded_forks else "No minimal-delta rebranded forks detected."
        ),
        evidence_urls=[r.get("html_url", "") for r in rebranded_forks if r.get("html_url")],
        benign_counter_hypothesis="Legitimate hackathon starter template or audited protocol fork (e.g., Uniswap/Compound fork) with thin config changes.",
    )

    inorganic_repos = []
    for r in repos:
        stars = int(r.get("stargazers_count", 0))
        issues = int(r.get("open_issues_count", 0)) + int(r.get("closed_issues_count", 0))
        prs = int(r.get("pr_count", 0))
        dt = parse_iso_utc(r.get("created_at"))
        age_d = (snap_time - dt).days if dt else 999
        if stars >= cfg["inorganic_star_min"] and age_d < 30 and (issues + prs) <= 1:
            inorganic_repos.append((r.get("full_name", ""), stars, age_d, r.get("html_url", "")))

    record_signal(
        "SIG-12", "4. Repository & Fork Provenance", "Inorganic Star-to-Activity Ratio",
        triggered=len(inorganic_repos) > 0,
        severity="MEDIUM", weight=10, confidence=0.70,
        evidence=(
            f"{len(inorganic_repos)} young repo(s) (<30d) have >={cfg['inorganic_star_min']} stars with <=1 total PR/issue: "
            + ", ".join(f"{n} ({s} stars, {d}d old)" for n, s, d, _ in inorganic_repos)
            if inorganic_repos else "Star counts align reasonably with repository age and public activity."
        ),
        evidence_urls=[x[3] for x in inorganic_repos if x[3]],
        benign_counter_hypothesis="Viral launch announcement or airdrop-farming community starring an official repo without opening issues.",
    )

    core_repos_no_pr = [
        r for r in repos
        if r.get("is_core_claimed", True) and int(r.get("pr_count", 0)) == 0 and int(r.get("closed_issues_count", 0)) == 0
    ]
    record_signal(
        "SIG-13", "4. Repository & Fork Provenance", "Missing Issue / PR Code Review Trail on Core Repo",
        triggered=len(core_repos_no_pr) > 0 and len(repos) > 0,
        severity="MEDIUM", weight=9, confidence=0.73,
        evidence=(
            f"{len(core_repos_no_pr)}/{len(repos)} declared core repo(s) have 0 public PRs and 0 closed issues: "
            + ", ".join(r.get("full_name", "") for r in core_repos_no_pr)
            if core_repos_no_pr else "Public PR / issue review history present across declared core repos."
        ),
        evidence_urls=[r.get("html_url", "") for r in core_repos_no_pr if r.get("html_url")],
        benign_counter_hypothesis="Small team pushing directly to main or conducting code review in a private upstream repo prior to public mirror.",
    )

    # --- Family 5: Cross-Contributor Network Graph (SIG-14..SIG-16) ---
    niche_repo_to_users: Dict[str, List[str]] = defaultdict(list)
    target_repo_names = {r.get("full_name", "").lower() for r in repos}
    for u in contributors:
        login = (u.get("login") or "").lower()
        for ext in u.get("external_repos", []):
            en = ext.lower()
            if en not in MAJOR_PUBLIC_OSS_REPOS and en not in target_repo_names:
                niche_repo_to_users[en].append(login)
    shared_niche = {k: sorted(set(v)) for k, v in niche_repo_to_users.items() if len(set(v)) >= 2}

    record_signal(
        "SIG-14", "5. Cross-Contributor Network Graph", "Shared Niche-Repo Overlap (Major OSS Excluded)",
        triggered=len(shared_niche) > 0,
        severity="MEDIUM", weight=12, confidence=0.76,
        evidence=(
            f"{len(shared_niche)} non-major external repo(s) shared by >=2 declared contributors: "
            + "; ".join(f"{k} ({', '.join(v)})" for k, v in list(shared_niche.items())[:4])
            if shared_niche else "No unexpected niche external repository overlap (major OSS repos excluded)."
        ),
        evidence_urls=[f"https://github.com/{k}" for k in list(shared_niche.keys())[:4]],
        benign_counter_hypothesis="Former colleagues from the same prior startup or university lab collaborating again on a new protocol.",
    )

    fast_approvals = []
    for pr in pull_requests:
        c_dt = parse_iso_utc(pr.get("created_at"))
        a_dt = parse_iso_utc(pr.get("approved_at"))
        if c_dt and a_dt and (a_dt - c_dt).total_seconds() <= cfg["fast_pr_approval_seconds"]:
            fast_approvals.append((pr.get("repo", ""), pr.get("number", ""), int((a_dt - c_dt).total_seconds()), pr.get("url", "")))

    record_signal(
        "SIG-15", "5. Cross-Contributor Network Graph", "Synchronized / Rubber-Stamp PR Approvals",
        triggered=len(fast_approvals) >= 2,
        severity="LOW", weight=8, confidence=0.65,
        evidence=(
            f"{len(fast_approvals)} PR(s) approved in <={cfg['fast_pr_approval_seconds']}s after creation."
            if len(fast_approvals) >= 2 else f"{len(fast_approvals)} rapid PR approval(s) (below threshold)."
        ),
        evidence_urls=[x[3] for x in fast_approvals if x[3]],
        benign_counter_hypothesis="Live synchronous screen-share review or trivial config/documentation hotfixes.",
    )

    addr_to_repos: Dict[str, set] = defaultdict(set)
    for c in scrubbed_commits:
        msg = c.get("message", "")
        for m in EVM_ADDR_RE.findall(msg):
            addr_to_repos[m.lower()].add(c["repo"])
        for m in TRON_ADDR_RE.findall(msg):
            addr_to_repos[m].add(c["repo"])
    recycled_addrs = {a: sorted(rs) for a, rs in addr_to_repos.items() if len(rs) >= 2}

    record_signal(
        "SIG-16", "5. Cross-Contributor Network Graph", "Recycled Wallet Addresses Across Public Commits",
        triggered=len(recycled_addrs) > 0,
        severity="MEDIUM", weight=11, confidence=0.77,
        evidence=(
            f"{len(recycled_addrs)} address(es) referenced across >=2 distinct repositories in commit metadata: "
            + "; ".join(f"{a[:10]}... ({len(rs)} repos)" for a, rs in list(recycled_addrs.items())[:4])
            if recycled_addrs else "No recycled wallet addresses detected across distinct repo commits."
        ),
        evidence_urls=[],
        benign_counter_hypothesis="Standard Hardhat/Foundry default test accounts (e.g., Anvil #0) or canonical mainnet token addresses referenced in deployment scripts.",
    )

    # --- Family 6: On-Chain Public Linkages (SIG-17..SIG-18) ---
    engine = VectorRiskEngine(label_db_path)
    grade_a_hits: List[Dict[str, Any]] = []
    adverse_ref_hits: List[Dict[str, Any]] = []
    onchain_assessments: List[Dict[str, Any]] = []
    try:
        for item in declared_addresses:
            chain = (item.get("chain") or "bsc").strip().lower()
            addr = (item.get("address") or "").strip()
            role = item.get("role") or "declared_address"
            if not addr:
                continue
            res = engine.assess_address(chain=chain, address=addr)
            onchain_assessments.append({"role": role, **res})
            for f in res["observed_facts"]:
                if f.get("grade") == "Grade-A":
                    grade_a_hits.append({"role": role, "chain": chain, "address": addr, **f})
                elif f.get("type") == "MIXER_CONTRACT":
                    adverse_ref_hits.append({"role": role, "chain": chain, "address": addr, **f})
            for s in res["analytical_signals"]:
                adverse_ref_hits.append({"role": role, "chain": chain, "address": addr, **s})
    finally:
        engine.close()

    record_signal(
        "SIG-17", "6. On-Chain Public Linkages", "Exact-Match Official Sanctions Screening (Grade-A OFAC SDN)",
        triggered=len(grade_a_hits) > 0,
        severity="CRITICAL", weight=85, confidence=0.99,
        evidence=(
            f"EXACT MATCH: {len(grade_a_hits)} declared address(es) matched Grade-A official sanctions list: "
            + "; ".join(f"{h['address']} ({h['chain']}, {h['label']})" for h in grade_a_hits)
            if grade_a_hits else f"0/{len(declared_addresses)} declared address(es) matched Grade-A OFAC SDN list."
        ),
        evidence_urls=[h.get("source_url", "") for h in grade_a_hits if h.get("source_url")],
        benign_counter_hypothesis="Exact official-list match requires immediate escalation to qualified legal/compliance counsel; verify address ownership and ensure the address was not mistakenly copied from public documentation.",
    )

    record_signal(
        "SIG-18", "6. On-Chain Public Linkages", "Adverse Public Reference / Mixer / Exploit Linkage",
        triggered=len(adverse_ref_hits) > 0,
        severity="HIGH", weight=35, confidence=0.80,
        evidence=(
            f"{len(adverse_ref_hits)} declared address(es) matched Grade-C mixer/exploit/adverse reference tags: "
            + "; ".join(f"{h['address'][:12]}... ({h.get('type')}: {h.get('label')})" for h in adverse_ref_hits[:4])
            if adverse_ref_hits else f"0/{len(declared_addresses)} declared address(es) carry adverse Grade-C explorer/mixer tags."
        ),
        evidence_urls=[h.get("source_url", "") for h in adverse_ref_hits if h.get("source_url")],
        benign_counter_hypothesis="Shared freelance deployment contractor, OTC broker, or unsolicited dust/tainted inbound transfers (receiving unsolicited funds does NOT prove common control).",
    )

    # Assemble verified observed facts
    observed_facts.append({
        "fact": "Public GitHub Scope Audited",
        "detail": f"{len(repos)} public repo(s), {len(contributors)} declared contributor(s), {len(scrubbed_commits)} commit(s), {len(pull_requests)} PR(s).",
    })
    observed_facts.append({
        "fact": "Official Sanctions Exact-Match Check (Grade-A)",
        "detail": f"{len(grade_a_hits)}/{len(declared_addresses)} declared address(es) matched Grade-A OFAC SDN in VectorLabelStore v1.0.",
    })
    observed_facts.append({
        "fact": "Privacy & Compliance Guardrail Check",
        "detail": "0 raw emails emitted; 0 nationality/language/ethnic-name features used.",
    })

    triggered_signals = [s for s in signals_eval if s["triggered"]]
    raw_score = min(100, sum(s["weight"] for s in triggered_signals))

    if grade_a_hits:
        triage_band = "CRITICAL_COMPLIANCE_ESCALATION"
        band_confidence = "High (Exact Grade-A Official List Match — verify legal applicability with counsel)"
    elif raw_score >= 45 or adverse_ref_hits:
        triage_band = "ELEVATED_REVIEW_RECOMMENDED"
        band_confidence = "Medium (Public-signal behavioral triage only — not an identity or legal finding)"
    elif raw_score >= 20:
        triage_band = "MODERATE_VERIFY_RECOMMENDED"
        band_confidence = "Medium-Low (Routine verification questions suggested)"
    else:
        triage_band = "LOW_RISK_NO_MAJOR_PUBLIC_ANOMALIES"
        band_confidence = "Medium (Low public-signal anomaly count; absence of signal != guarantee of safety)"

    # Build targeted, non-invasive verification checklist
    checklist = [
        "Confirm legal entity / authorized point of contact via standard KYB/KYC workflow (outside public GitHub signals).",
    ]
    if grade_a_hits:
        checklist.insert(0, "IMMEDIATE: Escalate exact Grade-A sanctions address match to qualified legal/compliance counsel before any listing, grant, or payment.")
    if any(s["signal_id"] in ("SIG-04", "SIG-05", "SIG-13") for s in triggered_signals):
        checklist.append("Conduct a live 20-minute technical architecture walkthrough of declared core contracts with the primary committer.")
    if any(s["signal_id"] in ("SIG-01", "SIG-02", "SIG-14") for s in triggered_signals):
        checklist.append("Request verifiable prior engineering portfolio or references for recently created contributor accounts.")
    if declared_addresses:
        checklist.append("Request cryptographic message signature (EIP-191 / EIP-712) proving control of declared deployer/treasury address(es).")
    if adverse_ref_hits:
        checklist.append("Request written explanation for any shared deployer/gas-funding or mixer-adjacent address history.")

    bundle_basis = {
        "engine_version": TRIAGE_ENGINE_VERSION,
        "target_name": snapshot.get("target_name", "unknown"),
        "snapshot_utc": snapshot.get("snapshot_utc", ""),
        "triage_band": triage_band,
        "triage_score": raw_score,
        "signals": signals_eval,
        "onchain_assessments": onchain_assessments,
    }
    ev_hash = canonical_sha256(bundle_basis)

    return {
        "schema_version": "vector-sg-track-b-triage-v1.0",
        "engine_version": TRIAGE_ENGINE_VERSION,
        "target_name": snapshot.get("target_name", "unknown"),
        "snapshot_utc": snapshot.get("snapshot_utc", snap_time.strftime("%Y-%m-%dT%H:%M:%SZ")),
        "triage_band": triage_band,
        "triage_score": raw_score,
        "band_confidence": band_confidence,
        "triggered_signal_count": len(triggered_signals),
        "total_signals_evaluated": len(signals_eval),
        "observed_facts": observed_facts,
        "signals": signals_eval,
        "triggered_signals": triggered_signals,
        "onchain_assessments": onchain_assessments,
        "verification_checklist": checklist,
        "prohibited_feature_audit": PROHIBITED_FEATURE_AUDIT,
        "calibration_disclosure": {
            "false_positive_baseline": "10/10 Low Risk on core open-source contributors (5 go-ethereum, 5 foundry).",
            "positive_recall_status": "UNMEASURED — no verified public covert state-sponsored GitHub ground truth exists; strictly triage/verification prioritization.",
            "execution_authority": "CLIENT_ONLY",
        },
        "evidence_hash": ev_hash,
    }
