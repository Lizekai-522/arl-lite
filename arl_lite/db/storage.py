"""arl_lite.db.storage

SQLite 存储封装,提供:
- 工作空间管理
- 任务 CRUD
- 资产 upsert(带 hash 去重 + first_seen/last_seen)
- 资产查询(支持简单过滤)
- 资产 diff(真 diff,基于 last_seen 对比)

纪律(抄自竞品分析):
- 失败不静默,3 态返回
- hash 去重键跨任务跨周期
- first_seen 永不变,last_seen 每次见到 UPDATE
- 5 列评分(抄 SF):hash / confidence / risk / source_hash / false_positive
"""
from __future__ import annotations

import sqlite3
import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime

log = logging.getLogger("arl_lite.storage")

# 本存储层自有 SQL 的默认执行预算(秒)。作用:挡住 WITH RECURSIVE 无限
# 递归这类 C 层死循环(连 SIGINT 都打不断)。规则引擎的 SQL 由
# correlation_engine._guarded_query 临时收紧到 5s,用完恢复本值。
# 取 120s 给 bulk_insert 这类长批量操作留足余量。
_SQL_DEFAULT_BUDGET_SECONDS = 120.0

# 默认 schema 路径
DEFAULT_SCHEMA = Path(__file__).parent / "schema.sql"
# 默认 workspace 根目录
def get_default_workspace_root() -> Path:
    """获取默认 workspace root(动态读 HOME,支持 test 修改 HOME)"""
    return Path.home() / ".arl-lite" / "workspaces"


DEFAULT_WORKSPACE_ROOT = get_default_workspace_root()


def compute_hash(*parts: str) -> str:
    """计算资产 hash(sha256 前 16 位)"""
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


# 用户提供的 SQL 片段(WHERE 子句)里禁止出现的写操作关键字。
# 检查在"剥离字符串字面量之后"的残留上做词边界匹配:
# 这样 `domain LIKE '%update%'` 不再误拦,而裸的 `drop table x` 仍然拦截。
# WITH 也禁:recursive CTE 可以在只读语句里无限循环,规则引擎有 5s 预算兜底,
# 用户 filter 直接禁掉最省心。
_FORBIDDEN_SQL_KEYWORDS = (
    "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE",
    "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REPLACE", "WITH",
)


def strip_sql_literals(sql: str) -> str:
    """把 SQL 里的 '...' / "..." 字面量替换成 ?,支持 '' 转义"""
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c in ("'", '"'):
            quote = c
            i += 1
            while i < n:
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:  # '' 转义
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("?")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_filter_sql(filter_sql: str) -> None:
    """校验用户提供的 WHERE 片段,不合法抛 ValueError

    规则:
    - 不允许多语句(;)
    - 字符串字面量之外不允许写操作关键字(词边界匹配)
    """
    residue = strip_sql_literals(filter_sql)
    if ";" in residue:
        raise ValueError("filter must be a single expression (';' not allowed)")
    upper = residue.upper()
    import re as _re
    for kw in _FORBIDDEN_SQL_KEYWORDS:
        if _re.search(rf"\b{kw}\b", upper):
            raise ValueError(f"filter contains forbidden keyword: {kw}")


class Storage:
    """SQLite 存储

    用法:
        storage = Storage(workspace="default")
        storage.add_domain(task_id=1, domain="api.example.com", source="crtsh")
        rows = storage.query("domains", filter="source='crtsh'")
    """

    def __init__(self, workspace: str = "default", workspace_root: Path | None = None):
        # 拒绝路径穿越 / 绝对路径
        if not workspace or not workspace.strip():
            raise ValueError("workspace name must not be empty")
        # 拦截 path separator 和 path component
        if "/" in workspace or "\\" in workspace:
            raise ValueError(f"workspace name must not contain path separators: {workspace!r}")
        # '..' 单独作为 component 时是 path traversal
        if workspace in (".", ".."):
            raise ValueError(f"workspace name must not be . or ..: {workspace!r}")
        # 检查 Path.resolve 后是否在 workspace_root 内
        self.workspace = workspace
        # 动态读 workspace_root(支持 test 改 HOME)
        if workspace_root:
            self.workspace_root = Path(workspace_root)
        else:
            self.workspace_root = get_default_workspace_root()
        self.workspace_dir = self.workspace_root / workspace
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        # 解析后必须仍在 workspace_root 内
        try:
            self.workspace_dir.resolve().relative_to(self.workspace_root.resolve())
        except ValueError:
            # 不在 root 内,删除已创建的目录防止误创建
            try:
                self.workspace_dir.rmdir()
            except OSError:
                pass
            raise ValueError(f"workspace path escapes workspace_root: {workspace!r}")
        self.db_path = self.workspace_dir / "data.db"
        self._local = threading.local()  # 每线程一条复用连接
        self._init_schema()
        self._init_default_workspace()

    def _init_schema(self) -> None:
        """初始化 schema"""
        if not DEFAULT_SCHEMA.exists():
            raise FileNotFoundError(f"schema.sql not found: {DEFAULT_SCHEMA}")
        schema_sql = DEFAULT_SCHEMA.read_text(encoding="utf-8")
        with self._conn() as conn:
            conn.executescript(schema_sql)
            log.debug(f"schema initialized at {self.db_path}")

    def _init_default_workspace(self) -> None:
        """确保当前 workspace 存在"""
        with self._conn() as conn:
            # INSERT OR IGNORE:两进程同时首次打开同一 workspace 时不再撞 UNIQUE
            cur = conn.execute(
                """INSERT OR IGNORE INTO workspaces (name, description, created_at, last_active_at)
                   VALUES (?, ?, ?, ?)""",
                (self.workspace, "auto-created", datetime.utcnow().isoformat(),
                 datetime.utcnow().isoformat())
            )
            if cur.rowcount > 0:
                log.info(f"workspace '{self.workspace}' created")
            self.workspace_id = conn.execute(
                "SELECT id FROM workspaces WHERE name = ?", (self.workspace,)
            ).fetchone()[0]
            # Migration: 给 correlations 加 UNIQUE 约束(如果缺)
            self._migrate_correlations_unique(conn)

    def _migrate_correlations_unique(self, conn) -> None:
        """如果 correlations 表缺 UNIQUE 约束,加进去

        旧 db 的 correlations 表可能:
        1. 缺 target / target_type / tags / advice 列
        2. 缺 UNIQUE 约束

        需要先 ALTER TABLE 加列(如果缺),再加 UNIQUE
        """
        idx = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='correlations'"
        ).fetchall()
        idx_names = {r["name"] for r in idx}
        has_unique_index = any("correlations_uniq" in n for n in idx_names)

        # 1. 补缺列(从 v0.2 → v0.3)
        cur_cols = {row["name"] for row in conn.execute("PRAGMA table_info(correlations)").fetchall()}
        # 迁移列 → 字面量 SQL 映射(列名/类型是代码写死的常量,不走 f-string 拼接)
        needed = {
            "target": "ALTER TABLE correlations ADD COLUMN target TEXT",
            "target_type": "ALTER TABLE correlations ADD COLUMN target_type TEXT",
            "headline": "ALTER TABLE correlations ADD COLUMN headline TEXT",
            "advice": "ALTER TABLE correlations ADD COLUMN advice TEXT",
            "tags": "ALTER TABLE correlations ADD COLUMN tags TEXT",
            "rule_description": "ALTER TABLE correlations ADD COLUMN rule_description TEXT",
            "matched_assets": "ALTER TABLE correlations ADD COLUMN matched_assets TEXT",
            "matched_count": "ALTER TABLE correlations ADD COLUMN matched_count INTEGER DEFAULT 0",
            "evidence": "ALTER TABLE correlations ADD COLUMN evidence TEXT",
        }
        for col, sql in needed.items():
            if col not in cur_cols:
                conn.execute(sql)
                log.info(f"migrated: correlations ADD COLUMN {col}")

        # Run even when the old UNIQUE index already exists. Keep surviving
        # legacy evidence active until a complete reevaluation can resolve it.
        lifecycle_columns = {
            "status": "ALTER TABLE correlations ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'resolved'))",
            "evaluated_run": "ALTER TABLE correlations ADD COLUMN evaluated_run TEXT",
            "resolved_run": "ALTER TABLE correlations ADD COLUMN resolved_run TEXT",
            "resolved_at": "ALTER TABLE correlations ADD COLUMN resolved_at TIMESTAMP",
        }
        needs_archive = "status" not in cur_cols
        for column, sql in lifecycle_columns.items():
            if column not in cur_cols:
                conn.execute(sql)
        if needs_archive:
            for row in conn.execute("SELECT * FROM correlations").fetchall():
                conn.execute(
                    """INSERT OR IGNORE INTO correlation_history
                       (workspace_id, rule_name, target, evaluated_run, status, snapshot, recorded_at)
                       VALUES (?, ?, ?, ?, 'active', ?, ?)""",
                    (row["workspace_id"], row["rule_name"], row["target"],
                     f"legacy-{row['id']}", json.dumps(dict(row), ensure_ascii=False),
                     datetime.utcnow().isoformat()),
                )
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_correlations_ws_status
                        ON correlations(workspace_id, status, rule_name)""")

        # 1b. sites 表补 server 列(关联分析 istio_no_auth 规则需要)
        site_cols = {row["name"] for row in conn.execute("PRAGMA table_info(sites)").fetchall()}
        if "server" not in site_cols:
            try:
                conn.execute("ALTER TABLE sites ADD COLUMN server TEXT")
                log.info("migrated: sites ADD COLUMN server")
            except Exception as e:
                log.warning(f"failed to add sites.server: {e}")

        if has_unique_index:
            return

        # 2. Legacy duplicates are archived above before keeping the latest row.
        try:
            conn.execute("""
                DELETE FROM correlations
                WHERE id NOT IN (
                    SELECT MAX(id) FROM correlations
                    GROUP BY workspace_id, rule_name, target
                )
            """)
        except Exception as e:
            log.debug(f"dedupe correlations: {e}")

        # 3. 加 unique index
        try:
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_correlations_uniq
                ON correlations(workspace_id, rule_name, target)
            """)
            log.info("migrated: added UNIQUE index on correlations")
        except Exception as e:
            log.warning(f"failed to add UNIQUE index: {e}")

    @contextmanager
    def _conn(self):
        """获取连接(线程内复用,自动 commit/rollback)

        每线程一条复用连接(sqlite3 默认禁止跨线程共用),避免逐行重连+重设
        PRAGMA 的开销。三个安全阀:
        1. busy timeout 30s:另一进程持写锁(如 bulk_insert 长事务)时等待
           而不是 5s 就抛 "database is locked" 丢数据
        2. 常驻 progress handler(默认 120s 预算,每次操作刷新):挡住
           `WITH RECURSIVE` 无限递归这类 C 层死循环——它连 SIGINT 都打不断,
           且挂死连接的读快照会阻止 WAL checkpoint 让 -wal 无限膨胀
        3. 连接身份校验:workspace 目录被删除后(rmtree 不受打开的 fd 影响),
           缓存连接会写进已删除 inode 造成"数据成功入库但消失"——每次操作
           前比对 (st_dev, st_ino),不一致立即重建
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None and not self._conn_is_current(conn):
            log.warning("workspace db file changed on disk (deleted/recreated?), reconnecting")
            try:
                conn.close()
            except Exception:
                pass
            conn = None
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")  # 提升并发
            # WAL 下 NORMAL 不会比 FULL 更容易损坏,只牺牲断电时最后一批事务
            conn.execute("PRAGMA synchronous = NORMAL")
            self._local.deadline = 0.0
            conn.set_progress_handler(
                lambda: 1 if time.monotonic() > self._local.deadline else 0, 10000)
            try:
                stat = self.db_path.stat()
                self._local.conn_identity = (stat.st_dev, stat.st_ino)
            except OSError:
                self._local.conn_identity = None
            self._local.conn = conn
        # 每次操作刷新预算(规则 SQL 用 _guarded_fetchall 临时收紧到 5s)
        self._local.deadline = time.monotonic() + _SQL_DEFAULT_BUDGET_SECONDS
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _conn_is_current(self, conn) -> bool:
        """缓存连接指向的文件是否还是当前 db_path(防幽灵文件写入)"""
        identity = getattr(self._local, "conn_identity", None)
        if identity is None:
            return True  # 建连时拿不到 stat(极端),不拦
        try:
            stat = self.db_path.stat()
        except OSError:
            return False  # 文件没了
        return (stat.st_dev, stat.st_ino) == identity

    def close(self) -> None:
        """关闭本线程的缓存连接(fd 卫生;长驻宿主/测试可在实例废弃时调用)"""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    # =========================
    # Workspace 管理
    # =========================

    def list_workspaces(self) -> list[dict]:
        """列出所有 workspace

        本项目 workspaces 注册表是每个库各自维护的:`workspace create` 写进
        default 库,而 `run -w foo` 的登记只存在于 foo 自己的 data.db 里。
        所以这里把「本库注册表」和「workspace_root 下的目录」做并集,
        目录里有 data.db 但不在注册表的也列出来(只读方式打开取元信息)。
        """
        rows: dict[str, dict] = {}
        with self._conn() as conn:
            for r in conn.execute(
                """SELECT w.id, w.name, w.description, w.ticket, w.valid_until,
                          w.created_at, w.last_active_at,
                          COUNT(DISTINCT t.id) AS task_count
                   FROM workspaces w
                   LEFT JOIN tasks t ON t.workspace_id = w.id
                   GROUP BY w.id"""
            ).fetchall():
                d = dict(r)
                rows[d["name"]] = d
        self._merge_dir_workspaces(rows)
        return sorted(rows.values(), key=lambda r: r.get("last_active_at") or "", reverse=True)

    def _merge_dir_workspaces(self, rows: dict[str, dict]) -> None:
        """把 workspace_root 下有 data.db 但不在本库注册表的 workspace 并进 rows;

        已在注册表、但有自己的 data.db 的(create 后又被 run 用的),也用
        自己库里的真实 task 数覆盖(default 库 JOIN 出来的恒为 0)
        """
        try:
            if not self.workspace_root.exists():
                return
            for d in sorted(self.workspace_root.iterdir()):
                if not d.is_dir():
                    continue
                db = d / "data.db"
                if not db.exists():
                    continue
                try:
                    # 只读打开别人的库,避免任何写入副作用;
                    # 路径做 URI 转义(? # 等字符会破坏 sqlite URI)
                    from urllib.parse import quote
                    uri = "file:" + quote(str(db)) + "?mode=ro"
                    conn = sqlite3.connect(uri, uri=True)
                    conn.row_factory = sqlite3.Row
                    try:
                        w = conn.execute(
                            "SELECT id, name, description, ticket, valid_until, created_at, last_active_at"
                            " FROM workspaces WHERE name = ? LIMIT 1", (d.name,)
                        ).fetchone()
                        task_count = 0
                        if w is not None:
                            task_count = conn.execute(
                                "SELECT COUNT(*) AS c FROM tasks WHERE workspace_id = ?",
                                (w["id"],)
                            ).fetchone()["c"]
                    finally:
                        conn.close()
                    if w is None:
                        continue
                    if d.name in rows:
                        # 注册表行:用自己的库刷新 task_count(更真实)
                        rows[d.name]["task_count"] = task_count
                    else:
                        rows[d.name] = {**dict(w), "task_count": task_count}
                except Exception as e:
                    log.debug(f"merge workspace dir {d.name} failed: {e}")
        except Exception as e:
            log.debug(f"workspace dir merge failed: {e}")

    def create_workspace(
        self,
        name: str,
        description: str = "",
        ticket: str | None = None,
        valid_from: str | None = None,
        valid_until: str | None = None,
    ) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO workspaces (name, description, ticket, valid_from, valid_until,
                                          created_at, last_active_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (name, description, ticket, valid_from, valid_until,
                 datetime.utcnow().isoformat(), datetime.utcnow().isoformat())
            )
            return cur.lastrowid

    def delete_workspace(self, workspace_id: int) -> bool:
        """删除 workspace(级联删除所有数据)

        注意:只删 workspaces 表记录,实际数据文件由调用方删
        """
        if not isinstance(workspace_id, int) or workspace_id <= 0:
            raise ValueError(f"workspace_id must be positive int (got {workspace_id!r})")
        with self._conn() as conn:
            # 先禁 FK(因为 ON DELETE CASCADE 应该处理,但保险起见显式删)
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
            return cur.rowcount > 0

    def delete_workspace_by_name(self, name: str) -> bool:
        """按名字删当前库里的 workspace 登记行

        注册表每库独立,调用方需要在 default 库和该库自己两处都清
        """
        if not name or not name.strip():
            raise ValueError("workspace name must not be empty")
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM workspaces WHERE name = ?", (name,))
            return cur.rowcount > 0

    # =========================
    # Task 管理
    # =========================

    def create_task(
        self,
        workspace_id: int,
        target: str,
        name: str = "",
        modules: list | str | None = None,
        config: dict | str | None = None,
        sources_total: int = 0,
    ) -> int:
        # 容错:list/dict → JSON 字符串
        if isinstance(modules, list):
            modules = json.dumps(modules, ensure_ascii=False)
        elif modules is None:
            modules = "[]"
        if isinstance(config, dict):
            config = json.dumps(config, ensure_ascii=False)
        elif config is None:
            config = "{}"
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO tasks (workspace_id, name, target, modules, config,
                                      sources_total, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'WAITING')""",
                (workspace_id, name or f"scan {target}", target, modules, config, sources_total)
            )
            return cur.lastrowid

    def update_task_status(
        self,
        task_id: int,
        status: str,
        started_at: str | None = None,
        finished_at: str | None = None,
        sources_ok: int | None = None,
        sources_failed: int | None = None,
        error_message: str | None = None,
    ) -> None:
        sets, params = [], []
        sets.append("status = ?"); params.append(status)
        if started_at: sets.append("started_at = ?"); params.append(started_at)
        if finished_at: sets.append("finished_at = ?"); params.append(finished_at)
        if sources_ok is not None: sets.append("sources_ok = ?"); params.append(sources_ok)
        if sources_failed is not None: sets.append("sources_failed = ?"); params.append(sources_failed)
        if error_message: sets.append("error_message = ?"); params.append(error_message)
        params.append(task_id)
        with self._conn() as conn:
            conn.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?", params)

    def get_task_status(self, task_id: int) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
            return row["status"] if row else None

    def list_tasks(self, workspace_id: int, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, name, target, status, sources_total, sources_ok, sources_failed,
                          started_at, finished_at
                   FROM tasks WHERE workspace_id = ?
                   ORDER BY id DESC LIMIT ?""",
                (workspace_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    # =========================
    # 资产 upsert(核心)
    # =========================

    # 各表允许被重扫刷新的业务字段。
    # TEXT 类:新值为空则保留旧值(COALESCE(NULLIF(...)));
    # PLAIN 类:直接取新值(端口状态/服务这类"变了就是要变")。
    _MUTABLE_TEXT: dict[str, tuple[str, ...]] = {
        "domains": ("resolved_ip",),
        "hosts": ("ip",),
        "sites": ("title", "server", "tech", "scheme", "ip"),
        "ports": ("version", "banner"),
        "findings": ("description", "evidence", "cve", "reference_url", "severity"),
    }
    _MUTABLE_PLAIN: dict[str, tuple[str, ...]] = {
        "ports": ("state", "service", "protocol"),
        "sites": ("status_code",),
    }

    def _upsert_asset(
        self,
        table: str,
        workspace_id: int,
        task_id: int,
        unique_key: str,
        hash_key: str,
        fields: dict,
        module: str,
        confidence: int = 50,
        risk: int = 0,
    ) -> bool:
        """统一 upsert 逻辑(hash 去重 + last_seen/业务字段刷新)

        单条 INSERT ... ON CONFLICT 原子完成,替代旧"先 SELECT 再 INSERT/UPDATE":
        - 修复并发 TOCTOU(两线程同时插同一新资产撞 UNIQUE)
        - 修复重扫不刷新业务字段(端口永 open / resolved_ip 永 None)

        Returns:
            True=新插入, False=已存在(仅刷新)
        """
        now = datetime.utcnow().isoformat()
        asset_hash = compute_hash(str(workspace_id), unique_key)

        cols = ["workspace_id", "task_id", "hash", "confidence", "risk",
                "module", "first_seen", "last_seen", "discovered_at"]
        values: list = [workspace_id, task_id, asset_hash, confidence, risk,
                        module, now, now, now]
        for k, v in fields.items():
            cols.append(k)
            values.append(v)
        placeholders = ", ".join(["?"] * len(cols))

        text_cols = self._MUTABLE_TEXT.get(table, ())
        plain_cols = self._MUTABLE_PLAIN.get(table, ())
        sets = ["last_seen = excluded.last_seen"]
        for k in fields:
            if k in plain_cols:
                sets.append(f"{k} = excluded.{k}")
            elif k in text_cols:
                sets.append(f"{k} = COALESCE(NULLIF(excluded.{k}, ''), {k})")
        update_clause = ", ".join(sets)

        with self._conn() as conn:
            existing = conn.execute(
                f"SELECT 1 FROM {table} WHERE hash = ?", (asset_hash,)
            ).fetchone()
            conn.execute(
                f"""INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})
                    ON CONFLICT(workspace_id, hash) DO UPDATE SET {update_clause}""",
                values
            )
            if existing:
                log.debug(f"upsert: {table} hash={asset_hash} first_seen kept, refreshed")
                return False
            log.debug(f"upsert: {table} hash={asset_hash} (new insert)")
            return True

    # ---------- 批量入库(Phase 7 性能优化)----------

    def bulk_insert(
        self,
        table: str,
        rows: list[dict],
        on_conflict: str = "ignore",
    ) -> dict:
        """批量插入(高吞吐,比逐行 upsert 快 10-50x)

        Args:
            table: 表名(domains/hosts/ports/sites/findings/correlations)
            rows: 行数据,每行 dict,key 必须包含表所有 NOT NULL 列
            on_conflict: "ignore" (跳过冲突) | "replace" (覆盖) | "update_ts" (仅更新 last_seen)

        Returns:
            dict {"inserted": N, "skipped": M, "errors": [...]}
        """
        # 防御:table 白名单
        ALLOWED_TABLES = {"domains", "hosts", "ports", "sites", "findings", "correlations"}
        if table not in ALLOWED_TABLES:
            raise ValueError(f"bulk_insert: table {table!r} not allowed (use {ALLOWED_TABLES})")
        if not isinstance(rows, list) or not rows:
            return {"inserted": 0, "skipped": 0, "errors": []}
        if on_conflict not in ("ignore", "replace", "update_ts"):
            raise ValueError(f"bulk_insert: on_conflict must be ignore|replace|update_ts, got {on_conflict!r}")

        now = datetime.utcnow().isoformat()
        inserted = 0
        skipped = 0
        errors = []

        # 表列名 alias:用户的 "source" 自动映射到 "module"
        # 用户的 "host"(在 ports 表)自动映射到 "ip"
        COLUMN_ALIAS = {
            "source": "module",  # 通用
        }
        if table == "ports":
            COLUMN_ALIAS["host"] = "ip"  # ports 用 ip,不是 host
        TABLES_WITH_MODULE = {"domains", "hosts", "ports", "sites", "findings"}

        with self._conn() as conn:
            # 列名白名单:只接受表里真实存在的列(防列名注入/拼写错静默丢列)。
            # table 已过上方 ALLOWED_TABLES 白名单;PRAGMA 用字面量映射,
            # 不拼接表名
            _PRAGMA_BY_TABLE = {
                "domains": "PRAGMA table_info(domains)",
                "hosts": "PRAGMA table_info(hosts)",
                "ports": "PRAGMA table_info(ports)",
                "sites": "PRAGMA table_info(sites)",
                "findings": "PRAGMA table_info(findings)",
                "correlations": "PRAGMA table_info(correlations)",
            }
            valid_cols = {r["name"] for r in conn.execute(_PRAGMA_BY_TABLE[table]).fetchall()}
            # 分批提交:单事务持写锁过长会让其他进程撞 "database is locked"
            BATCH = 500
            # 一次事务内全部 execute,大幅提升吞吐
            for i, row in enumerate(rows):
                if i and i % BATCH == 0:
                    conn.commit()
                # 关键:每行独立 dict,避免累积 mutation
                row = dict(row)
                try:
                    # 应用列名 alias:source → module, ports.host → ports.ip
                    for old, new in COLUMN_ALIAS.items():
                        if old in row and new not in row:
                            row[new] = row.pop(old)
                    unknown = set(row.keys()) - valid_cols
                    if unknown:
                        errors.append(f"row {i}: unknown columns {sorted(unknown)} (valid: {sorted(valid_cols)})")
                        continue
                    # 自动填工作空间 + 时间戳(只补该表实际存在的列——
                    # correlations 用 detected_at 且无 hash 列,旧逻辑
                    # 无条件补 discovered_at/first_seen 导致 bulk_insert
                    # 对该表恒失败)
                    row.setdefault("workspace_id", self.workspace_id)
                    for ts_col in ("discovered_at", "last_seen", "first_seen", "detected_at"):
                        if ts_col in valid_cols:
                            row.setdefault(ts_col, now)
                    if "hash" in valid_cols and "hash" not in row:
                        # 自动用表典型 unique key 算 hash
                        # 注意:列名 alias 已生效,ports 表此时键是 ip(不是 host)
                        if table == "findings":
                            unique = f"{row.get('target', '')}|{row.get('finding_type', '')}|{row.get('title', '')}"
                        elif table == "ports":
                            unique = f"{row.get('ip', '')}:{row.get('port', '')}"
                        elif table == "sites":
                            unique = row.get("url", "")
                        elif table == "correlations":
                            unique = f"{row.get('rule_name', '')}|{row.get('target', '')}"
                        else:
                            unique = row.get("host") or row.get("domain") or row.get("name") or str(i)
                        row["hash"] = compute_hash(str(self.workspace_id), unique)

                    if on_conflict == "ignore":
                        cols = list(row.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_str = ", ".join(cols)
                        try:
                            cur = conn.execute(
                                f"INSERT INTO {table} ({col_str}) VALUES ({placeholders})",
                                list(row.values()),
                            )
                            inserted += 1
                        except sqlite3.IntegrityError as e:
                            msg = str(e).lower()
                            if "unique" in msg or "conflict" in msg:
                                # UNIQUE 冲突 = 重复,跳过
                                skipped += 1
                            else:
                                # 其他约束(NOT NULL / FK / CHECK) = 真错
                                errors.append(f"row {i}: {type(e).__name__}: {e}")
                                if len(errors) > 10:
                                    errors.append("... truncated")
                                    break
                    elif on_conflict == "replace":
                        cols = list(row.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_str = ", ".join(cols)
                        conn.execute(
                            f"INSERT OR REPLACE INTO {table} ({col_str}) VALUES ({placeholders})",
                            list(row.values()),
                        )
                        inserted += 1
                    elif on_conflict == "update_ts":
                        cols = list(row.keys())
                        placeholders = ", ".join(["?"] * len(cols))
                        col_str = ", ".join(cols)
                        cur = conn.execute(
                            f"INSERT INTO {table} ({col_str}) VALUES ({placeholders}) "
                            f"ON CONFLICT(hash) DO UPDATE SET last_seen = ?",
                            list(row.values()) + [now],
                        )
                        if cur.rowcount > 0:
                            inserted += 1
                        else:
                            skipped += 1
                except Exception as e:
                    errors.append(f"row {i}: {type(e).__name__}: {e}")
                    if len(errors) > 10:  # 限 10 条
                        errors.append("... truncated")
                        break
        return {"inserted": inserted, "skipped": skipped, "errors": errors}

    # ---------- Domain ----------

    def add_domain(
        self,
        task_id: int,
        domain: str,
        source: str,
        resolved_ip: str | None = None,
        confidence: int = 50,
        risk: int = 0,
        source_hash: str | None = None,
    ) -> bool:
        if not domain or not domain.strip():
            raise ValueError("domain must not be empty")
        if len(domain) > 253:
            raise ValueError(f"domain too long: {len(domain)} > 253")
        if "\x00" in domain:
            raise ValueError("domain must not contain null byte")
        workspace_id = self.workspace_id
        return self._upsert_asset(
            "domains", workspace_id, task_id,
            unique_key=domain,
            hash_key=domain,
            fields={
                "domain": domain,
                "source": source,
                "resolved_ip": resolved_ip,
                "source_hash": source_hash or "ROOT",
            },
            module=source,
            confidence=confidence,
            risk=risk,
        )

    # ---------- Host ----------

    def add_host(
        self,
        task_id: int,
        host: str,
        ip: str | None = None,
        source: str = "portscan",
        confidence: int = 60,
        risk: int = 0,
    ) -> bool:
        """入库 host(关联域名↔IP)"""
        if not host or not host.strip():
            raise ValueError("host must not be empty")
        if len(host) > 253:
            raise ValueError(f"host too long: {len(host)} > 253")
        if "\x00" in host:
            raise ValueError("host must not contain null byte")
        if ip and "\x00" in ip:
            raise ValueError("ip must not contain null byte")
        workspace_id = self.workspace_id
        return self._upsert_asset(
            "hosts", workspace_id, task_id,
            unique_key=host,
            hash_key=host,
            fields={
                "host": host,
                "ip": ip,
            },
            module=source,
            confidence=confidence,
            risk=risk,
        )

    # ---------- Port ----------

    def add_port(
        self,
        task_id: int,
        host: str,  # IP 或 host(为了兼容域名)
        port: int,
        state: str = "open",
        service: str = "unknown",
        protocol: str = "tcp",
        version: str | None = None,
        banner: str | None = None,
        source: str = "portscan",
        confidence: int = 60,
        risk: int = 0,
    ) -> bool:
        """入库 port

        设计:hash 用 (host, port) 唯一约束,这样域名+port 也能去重
        """
        if not host or not host.strip():
            raise ValueError("host must not be empty")
        if "\x00" in host:
            raise ValueError("host must not contain null byte")
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError(f"port must be int (got {type(port).__name__}: {port!r})")
        if not (0 < port < 65536):
            raise ValueError(f"port out of range: {port} (must be 1..65535)")
        workspace_id = self.workspace_id
        return self._upsert_asset(
            "ports", workspace_id, task_id,
            unique_key=f"{host}:{port}",
            hash_key=f"{host}:{port}",
            fields={
                "ip": host,  # schema 字段是 ip,但接受域名也行
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "banner": banner,
                "module": source,
            },
            module=source,
            confidence=confidence,
            risk=risk,
        )

    # ---------- Finding ----------

    def add_finding(
        self,
        task_id: int,
        target: str,
        finding_type: str,
        title: str = "",
        description: str = "",
        evidence: str | None = None,
        target_type: str = "site",
        severity: str = "info",
        cve: str | None = None,
        reference_url: str | None = None,
        source: str = "fingerprint",
        confidence: int = 50,
        risk: int = 0,
    ) -> bool:
        """入库 finding(指纹/Vuln/泄漏/Subtakeover 等)

        Args:
            target: 命中的资产标识(URL/host/port 等)
            finding_type: VULN / LEAK / TAKEOVER / MISCONFIG / FINGERPRINT
            title: 短描述
            description: 详细描述
            evidence: 证据(JSON/原始 payload)
            target_type: domain/host/port/site
            severity: info/low/medium/high/critical

        Raises:
            ValueError: 必填字段为空 / 含 null byte / 超长
        """
        # 防御:必填字段
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"add_finding: target must be non-empty str (got {type(target).__name__})")
        if not isinstance(finding_type, str) or not finding_type.strip():
            raise ValueError(f"add_finding: finding_type must be non-empty str (got {type(finding_type).__name__})")
        # None 容错(调用方自然取值,签名默认 "" 不代表 None 合法)
        title = title if title is not None else ""
        description = description if description is not None else ""
        if "\x00" in target or "\x00" in finding_type or "\x00" in title:
            raise ValueError("add_finding: null byte not allowed in target/finding_type/title")
        # 长度限制
        if len(target) > 1000:
            raise ValueError(f"add_finding: target too long ({len(target)} > 1000)")
        if len(finding_type) > 100:
            raise ValueError(f"add_finding: finding_type too long ({len(finding_type)} > 100)")
        if len(title) > 500:
            raise ValueError(f"add_finding: title too long ({len(title)} > 500)")
        if len(description) > 5000:
            raise ValueError(f"add_finding: description too long ({len(description)} > 5000)")
        # evidence 类型 + 长度
        if evidence is not None and not isinstance(evidence, (str, bytes)):
            raise ValueError(f"add_finding: evidence must be str/bytes (got {type(evidence).__name__})")
        if isinstance(evidence, bytes) and len(evidence) > 50000:
            raise ValueError(f"add_finding: evidence bytes too long ({len(evidence)} > 50000)")
        if isinstance(evidence, str) and len(evidence) > 50000:
            evidence = evidence[:50000]
        # severity 规范化(未知 → info)
        KNOWN_SEVERITY = {"info", "low", "medium", "high", "critical"}
        if severity not in KNOWN_SEVERITY:
            severity = "info"
        workspace_id = self.workspace_id
        unique = f"{target}|{finding_type}|{title}"
        return self._upsert_asset(
            "findings", workspace_id, task_id,
            unique_key=unique,
            hash_key=unique,
            fields={
                "module": source,
                "finding_type": finding_type,
                "target": target,
                "target_type": target_type,
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "cve": cve,
                "reference_url": reference_url,
            },
            module=source,
            confidence=confidence,
            risk=risk,
        )

    # ---------- Site ----------

    def add_site(
        self,
        task_id: int,
        url: str,
        host: str,
        ip: str | None,
        port: int | None,
        scheme: str,
        title: str = "",
        status_code: int = 0,
        server: str | None = None,
        tech: str | None = None,
        module: str = "httpx",
        confidence: int = 50,
        risk: int = 0,
    ) -> bool:
        workspace_id = self.workspace_id
        return self._upsert_asset(
            "sites", workspace_id, task_id,
            unique_key=url,
            hash_key=url,
            fields={
                "url": url,
                "host": host,
                "ip": ip,
                "port": port,
                "scheme": scheme,
                "title": title,
                "server": server,
                "status_code": status_code,
                "tech": tech,
            },
            module=module,
            confidence=confidence,
            risk=risk,
        )

    # =========================
    # 死源状态
    # =========================

    def record_source_status(
        self,
        task_id: int,
        source_name: str,
        ok: bool,
        source_type: str = "passive",
        found_count: int = 0,
        duration_seconds: float = 0.0,
        error_type: str | None = None,
        error_message: str | None = None,
        enabled: bool = True,
    ) -> None:
        workspace_id = self.workspace_id
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO source_status
                   (task_id, workspace_id, source_name, source_type, ok, enabled,
                    found_count, duration_seconds, error_type, error_message,
                    started_at, finished_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (task_id, workspace_id, source_name, source_type, int(ok), int(enabled),
                 found_count, duration_seconds, error_type, error_message, now, now)
            )

    # =========================
    # 查询
    # =========================

    def query(
        self,
        table: str,
        filter_sql: str | None = None,
        limit: int = 50,
        workspace_id: int | None = None,
    ) -> list[dict]:
        """通用查询(带白名单,禁止 DROP/DELETE/UPDATE)

        Args:
            table: 表名(白名单:domains/hosts/ports/sites/findings/tasks/source_status/correlations)
            filter_sql: 可选 WHERE 子句(不含 WHERE 关键字)
            limit: 最大行数
        """
        ALLOWED = {"domains", "hosts", "ports", "sites", "findings",
                   "tasks", "source_status", "correlations", "correlation_history", "asset_changes",
                   "workspaces", "monitors", "schedules"}
        if table not in ALLOWED:
            raise ValueError(f"table '{table}' not in whitelist: {sorted(ALLOWED)}")

        ws = workspace_id or self.workspace_id
        if not isinstance(limit, int) or limit < 0 or limit > 10000:
            raise ValueError(f"limit must be int 0..10000, got {limit!r}")
        sql = f"SELECT * FROM {table} WHERE workspace_id = ?"
        params: list = [ws]
        if filter_sql:
            check_filter_sql(filter_sql)
            sql += f" AND ({filter_sql})"
        sql += f" ORDER BY id DESC LIMIT {int(limit)}"
        with self._conn() as conn:
            try:
                rows = conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError as e:
                # 引号不闭合/语法错给干净的 ValueError(main 统一转 exit 2),
                # 不然用户看到的是全栈 Traceback
                raise ValueError(f"filter SQL 无效: {e}") from e
        return [dict(r) for r in rows]

    # ---------- 全文搜索(FTS5)----------

    def search(
        self,
        table: str,        # "sites" | "domains" | "findings"
        keyword: str,
        limit: int = 50,
    ) -> list[dict]:
        FTS_TABLES = {"sites": "sites_fts", "domains": "domains_fts", "findings": "findings_fts"}
        if table not in FTS_TABLES:
            raise ValueError(f"FTS not available for {table}")
        fts_table = FTS_TABLES[table]
        # FTS5 特殊字符: . , : ; ! ? * " ( ) [ ] { } ^ $ - + |
        # 用双引号包整个 phrase,FTS5 双引号内特殊字符视为字面量
        # 内部双引号转义为 ""
        if not keyword or not keyword.strip():
            return []
        safe = keyword.strip().replace('"', '""')
        fts_query = f'"{safe}"'
        sql = f"""SELECT {table}.* FROM {table}
                  JOIN {fts_table} ON {fts_table}.rowid = {table}.id
                  WHERE {fts_table} MATCH ? AND {table}.workspace_id = ?
                  ORDER BY rank LIMIT {int(limit)}"""
        with self._conn() as conn:
            try:
                rows = conn.execute(sql, (fts_query, self.workspace_id)).fetchall()
            except Exception as e:
                log.warning(f"FTS5 search failed for keyword {keyword!r}: {e}")
                # fallback: 退到 LIKE 搜索(各表实际存在的列,别再引用不存在的列)
                searchable = {
                    "domains": ("domain", "source"),
                    "sites": ("url", "title", "host", "tech", "server"),
                    "findings": ("title", "description", "target", "finding_type", "cve"),
                }[table]
                like = f"%{keyword}%"
                where = " OR ".join(f"{c} LIKE ?" for c in searchable)
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE workspace_id = ? AND ({where}) "
                    f"ORDER BY id DESC LIMIT {int(limit)}",
                    (self.workspace_id, *([like] * len(searchable))),
                ).fetchall()
        return [dict(r) for r in rows]

    # =========================
    # 真 diff(基于 last_seen)
    # =========================

    def diff_new_since(self, since_iso: str, table: str = "domains",
                        workspace_id: int | None = None) -> list[dict]:
        ws = workspace_id or self.workspace_id
        ALLOWED = {"domains", "hosts", "ports", "sites", "findings"}
        if table not in ALLOWED:
            raise ValueError(f"table '{table}' not allowed for diff")
        # 防御:since_iso 校验(必须 ISO 格式)
        if not isinstance(since_iso, str) or not since_iso.strip():
            raise ValueError(f"since_iso must be non-empty str (got {type(since_iso).__name__})")
        try:
            from datetime import datetime
            datetime.fromisoformat(since_iso)
        except (ValueError, TypeError) as e:
            raise ValueError(f"invalid ISO timestamp {since_iso!r}: {e}")
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE workspace_id = ? AND first_seen >= ?",
                (ws, since_iso)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """获取 workspace 资产统计"""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT
                    (SELECT COUNT(*) FROM domains WHERE workspace_id = ?) AS domains,
                    (SELECT COUNT(*) FROM hosts WHERE workspace_id = ?) AS hosts,
                    (SELECT COUNT(*) FROM ports WHERE workspace_id = ?) AS ports,
                    (SELECT COUNT(*) FROM sites WHERE workspace_id = ?) AS sites,
                    (SELECT COUNT(*) FROM findings WHERE workspace_id = ?) AS findings,
                    (SELECT COUNT(*) FROM tasks WHERE workspace_id = ?) AS tasks,
                    (SELECT COUNT(*) FROM correlations WHERE workspace_id = ?) AS correlations
                """,
                (self.workspace_id,) * 7
            ).fetchone()
        return dict(row)
