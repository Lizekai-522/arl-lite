-- ============================================================================
-- arl-lite SQLite Schema v1.0
-- ----------------------------------------------------------------------------
-- 信源:smicallef/spiderfoot db.py:74 + Aabyss-Team/ARL 字段借鉴 + 自建监控 diff
-- 纪律:
--   1. 每条资产带 hash 去重键 + workspace_id(跨任务跨周期去重)
--   2. first_seen 永不变,last_seen 每次见到就 UPDATE
--   3. confidence/risk/false_positive 三评分对齐 SF
--   4. source_hash 溯源链,根事件 ROOT
--   5. 所有表带 workspace_id 索引
-- 设计:单文件 SQLite,无 schema migration v2 时整体替换
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. workspaces —— 工作空间(每个目标一个独立数据集)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    -- 授权元数据(抄自 COMPETITOR_ANALYSIS #4,合规先于功能)
    ticket TEXT,                       -- 授权凭证号 PENTEST-2026-001
    issued_by TEXT,                    -- 授权方
    valid_from TIMESTAMP,
    valid_until TIMESTAMP,
    contact TEXT,                      -- 应急联系人
    -- 时间戳
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. tasks —— 任务调度表(状态机:WAITING → RUNNING → DONE/FAILED/STOPPED)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    name TEXT,
    target TEXT NOT NULL,              -- 域名/IP/URL
    modules TEXT,                      -- JSON 数组,模块列表
    preset TEXT,                       -- preset 名
    config TEXT,                       -- JSON,模块配置覆盖
    status TEXT DEFAULT 'WAITING',     -- WAITING/RUNNING/DONE/DONE_PARTIAL/FAILED/STOPPED
    progress INTEGER DEFAULT 0,        -- 0-100
    sources_total INTEGER DEFAULT 0,   -- 计划跑的源数
    sources_ok INTEGER DEFAULT 0,      -- 成功的源数(死源可见)
    sources_failed INTEGER DEFAULT 0,  -- 失败的源数
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tasks_ws_status ON tasks(workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target);

-- ----------------------------------------------------------------------------
-- 3. domains —— 子域资产表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    domain TEXT NOT NULL,
    source TEXT,                       -- subfinder / crtsh / fofa / ...
    resolved_ip TEXT,
    -- 抄 SF 5 列 + 自建 2 列
    hash TEXT NOT NULL,                -- sha256(workspace_id+domain) 跨任务去重
    confidence INTEGER DEFAULT 50,    -- 0-100,抄 SF
    risk INTEGER DEFAULT 0,            -- 0-10,抄 SF
    source_hash TEXT,                  -- 溯源链,根事件 ROOT
    module TEXT,                       -- 产生者模块
    false_positive INTEGER DEFAULT 0, -- 误报标记
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, hash),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_domains_hash ON domains(hash);
CREATE INDEX IF NOT EXISTS idx_domains_ws_first ON domains(workspace_id, first_seen);
CREATE INDEX IF NOT EXISTS idx_domains_ws_source ON domains(workspace_id, source);
CREATE INDEX IF NOT EXISTS idx_domains_risk ON domains(risk DESC);

-- ----------------------------------------------------------------------------
-- 4. hosts —— 主机表(domain + IP)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    host TEXT NOT NULL,
    ip TEXT,
    asn TEXT,
    geo_country TEXT,
    geo_city TEXT,
    -- 5 列 + 2 列
    hash TEXT NOT NULL,                -- sha256(workspace_id+host)
    confidence INTEGER DEFAULT 50,
    risk INTEGER DEFAULT 0,
    source_hash TEXT,
    module TEXT,
    false_positive INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, hash),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hosts_hash ON hosts(hash);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_ws_first ON hosts(workspace_id, first_seen);

-- ----------------------------------------------------------------------------
-- 5. ports —— 端口资产表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',       -- tcp/udp
    state TEXT DEFAULT 'open',         -- open/closed/filtered
    service TEXT,                      -- http / ssh / mysql / ...
    version TEXT,                      -- Apache 2.4.49
    banner TEXT,
    -- 5 列 + 2 列
    hash TEXT NOT NULL,                -- sha256(workspace_id+ip+port)
    confidence INTEGER DEFAULT 50,
    risk INTEGER DEFAULT 0,
    source_hash TEXT,
    module TEXT,                       -- nmap / naabu / portscan
    false_positive INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, hash),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ports_hash ON ports(hash);
CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);
CREATE INDEX IF NOT EXISTS idx_ports_ws_first ON ports(workspace_id, first_seen);
CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service);
CREATE INDEX IF NOT EXISTS idx_ports_risk ON ports(risk DESC);

-- ----------------------------------------------------------------------------
-- 6. sites —— Web 站点表(URL + 技术栈)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    url TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    port INTEGER,
    scheme TEXT,                       -- http/https
    title TEXT,
    server TEXT,                       -- HTTP Server header(用于关联分析)
    status_code INTEGER,
    content_length INTEGER,
    tech TEXT,                         -- JSON,指纹结果
    response_headers TEXT,            -- JSON,响应头
    body_hash TEXT,                    -- 用于 site_change 检测
    screenshot_path TEXT,
    -- 5 列 + 2 列(标准 7 列)
    hash TEXT NOT NULL,                -- sha256(workspace_id+url)
    confidence INTEGER DEFAULT 50,
    risk INTEGER DEFAULT 0,
    source_hash TEXT,
    module TEXT,
    false_positive INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, hash),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sites_hash ON sites(hash);
CREATE INDEX IF NOT EXISTS idx_sites_ws_host ON sites(workspace_id, host);
CREATE INDEX IF NOT EXISTS idx_sites_ip ON sites(ip);
CREATE INDEX IF NOT EXISTS idx_sites_ws_url ON sites(workspace_id, url);
CREATE INDEX IF NOT EXISTS idx_sites_ws_first ON sites(workspace_id, first_seen);
CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status_code);
CREATE INDEX IF NOT EXISTS idx_sites_risk ON sites(risk DESC);

-- ----------------------------------------------------------------------------
-- 7. findings —— 漏洞/发现(替代 SF 的 events 表)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    module TEXT NOT NULL,              -- 产生模块
    finding_type TEXT NOT NULL,        -- VULN / LEAK / TAKEOVER / MISCONFIG
    target TEXT NOT NULL,              -- 命中的资产标识
    target_type TEXT,                  -- domain/host/port/site
    severity TEXT,                     -- info/low/medium/high/critical
    title TEXT,
    description TEXT,
    evidence TEXT,                     -- JSON,PoC 数据
    cve TEXT,                          -- CVE-2024-1234
    reference_url TEXT,
    -- 5 列 + 2 列
    hash TEXT NOT NULL,                -- sha256(workspace_id+target+finding_type)
    confidence INTEGER DEFAULT 50,
    risk INTEGER DEFAULT 0,
    source_hash TEXT,
    false_positive INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, hash),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
CREATE INDEX IF NOT EXISTS idx_findings_ws_sev ON findings(workspace_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);

-- ----------------------------------------------------------------------------
-- 8. source_status —— 死源状态表(零假数据纪律)
-- 每源每任务一行,记录本轮是否成功 + 失败原因
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    workspace_id INTEGER NOT NULL,
    source_name TEXT NOT NULL,         -- crtsh / fofa / subfinder
    source_type TEXT,                  -- passive / active / token-required
    ok INTEGER DEFAULT 0,              -- 0/1
    enabled INTEGER DEFAULT 1,         -- 用户是否启用
    found_count INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    error_type TEXT,                   -- timeout / 401 / 429 / 500 / network / unknown
    error_message TEXT,
    rate_limit_hit INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_source_status_task ON source_status(task_id);
CREATE INDEX IF NOT EXISTS idx_source_status_ws_ok ON source_status(workspace_id, ok);

-- ----------------------------------------------------------------------------
-- 9. asset_changes —— 变更事件表(真 diff,替代"定期重扫冒充监控")
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    asset_hash TEXT NOT NULL,
    asset_type TEXT NOT NULL,          -- domain/host/port/site/finding
    change_type TEXT NOT NULL,         -- NEW_ASSET / DISAPPEARED / TITLE_CHANGED / TECH_CHANGED / FINGERPRINT_CHANGED / STATUS_CHANGED
    before_value TEXT,                -- JSON,变更前快照
    after_value TEXT,                 -- JSON,变更后快照
    diff TEXT,                         -- JSON,字段级 diff
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detected_by_task_id INTEGER,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_changes_ws_type ON asset_changes(workspace_id, change_type, detected_at);
CREATE INDEX IF NOT EXISTS idx_changes_ws_hash ON asset_changes(workspace_id, asset_hash);
CREATE INDEX IF NOT EXISTS idx_changes_asset_type ON asset_changes(workspace_id, asset_type);

-- ----------------------------------------------------------------------------
-- 10. monitors —— 周期监控配置
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    monitor_type TEXT DEFAULT 'full',  -- full / subdomain / port / site
    interval_seconds INTEGER DEFAULT 86400,  -- 默认 24h
    last_run_at TIMESTAMP,
    last_change_count INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    notify_webhook TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitors_ws_enabled ON monitors(workspace_id, enabled);

-- ----------------------------------------------------------------------------
-- 11. schedules —— 周期任务配置(cron)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    cron TEXT NOT NULL,                -- "0 2 * * *"
    task_config TEXT NOT NULL,         -- JSON,任务配置
    enabled INTEGER DEFAULT 1,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_schedules_ws_enabled ON schedules(workspace_id, enabled);

-- ----------------------------------------------------------------------------
-- 12. correlations —— 关联分析结果(SF correlations 30 条规则的执行结果)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    task_id INTEGER,
    rule_name TEXT NOT NULL,           -- exposed_storage / exposed_database ...
    rule_description TEXT,
    risk INTEGER DEFAULT 0,            -- 0-10
    target TEXT,                       -- 命中目标(ip/host/domain/url)
    target_type TEXT,                  -- ip/host/domain/site
    headline TEXT,                     -- 渲染好的标题
    advice TEXT,                       -- 处置建议
    tags TEXT,                         -- JSON array
    matched_assets TEXT,               -- JSON,命中的资产
    matched_count INTEGER DEFAULT 0,
    evidence TEXT,                     -- JSON,执行引擎的中间结果
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'resolved')),
    evaluated_run TEXT,                -- UUID of latest successful matching evaluation
    resolved_run TEXT,                 -- successful evaluation that closed this hit
    resolved_at TIMESTAMP,
    UNIQUE(workspace_id, rule_name, target),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_correlations_ws_rule ON correlations(workspace_id, rule_name);
CREATE INDEX IF NOT EXISTS idx_correlations_ws_risk ON correlations(workspace_id, risk DESC);

-- Append-only evidence snapshots; the correlations table is the latest state.
CREATE TABLE IF NOT EXISTS correlation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    target TEXT,
    evaluated_run TEXT NOT NULL,
    status TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    recorded_at TIMESTAMP NOT NULL,
    UNIQUE(workspace_id, rule_name, target, evaluated_run, status),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_correlation_history_ws_rule
ON correlation_history(workspace_id, rule_name);

-- ----------------------------------------------------------------------------
-- 13. fingerprints —— 指纹规则缓存(避免每次重新解析 webapp.json)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,         -- "Nginx" / "WordPress" / "Spring Boot"
    category TEXT,                     -- "Web server" / "CMS" / "Framework"
    match_headers TEXT,                -- JSON 数组
    match_html TEXT,                   -- JSON 数组
    match_title TEXT,                  -- JSON 数组
    match_body TEXT,                   -- JSON 数组
    version_regex TEXT,                -- 版本提取正则
    source TEXT,                       -- arl / wappalyzer / custom
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_cat ON fingerprints(category);
CREATE INDEX IF NOT EXISTS idx_fingerprints_source ON fingerprints(source);

-- ----------------------------------------------------------------------------
-- 14. scope —— 授权范围(独立于 workspace,集中管理)
-- 一个 YAML 文件可关联多个 workspace
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scope_authorization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    ticket TEXT NOT NULL,              -- 授权凭证号
    issued_by TEXT,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    allowed_domains TEXT,              -- JSON 数组
    allowed_ips TEXT,                  -- JSON 数组
    excluded_targets TEXT,             -- JSON 数组(白名单:不扫)
    contact TEXT,                      -- 应急联系人
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scope_ws_ticket ON scope_authorization(workspace_id, ticket);

-- ============================================================================
-- FTS5 虚表(全文搜索,只挂文本列)
-- ============================================================================

-- 站点全文搜索
CREATE VIRTUAL TABLE IF NOT EXISTS sites_fts USING fts5(
    url, title, tech,
    content='sites', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- 域名全文搜索
CREATE VIRTUAL TABLE IF NOT EXISTS domains_fts USING fts5(
    domain,
    content='domains', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- 漏洞全文搜索
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, description, target, cve,
    content='findings', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- FTS 触发器:同步主表增删改
-- sites
CREATE TRIGGER IF NOT EXISTS sites_ai AFTER INSERT ON sites BEGIN
    INSERT INTO sites_fts(rowid, url, title, tech) VALUES (new.id, new.url, new.title, new.tech);
END;
CREATE TRIGGER IF NOT EXISTS sites_ad AFTER DELETE ON sites BEGIN
    INSERT INTO sites_fts(sites_fts, rowid, url, title, tech) VALUES ('delete', old.id, old.url, old.title, old.tech);
END;
CREATE TRIGGER IF NOT EXISTS sites_au AFTER UPDATE ON sites BEGIN
    INSERT INTO sites_fts(sites_fts, rowid, url, title, tech) VALUES ('delete', old.id, old.url, old.title, old.tech);
    INSERT INTO sites_fts(rowid, url, title, tech) VALUES (new.id, new.url, new.title, new.tech);
END;

-- domains
CREATE TRIGGER IF NOT EXISTS domains_ai AFTER INSERT ON domains BEGIN
    INSERT INTO domains_fts(rowid, domain) VALUES (new.id, new.domain);
END;
CREATE TRIGGER IF NOT EXISTS domains_ad AFTER DELETE ON domains BEGIN
    INSERT INTO domains_fts(domains_fts, rowid, domain) VALUES ('delete', old.id, old.domain);
END;
CREATE TRIGGER IF NOT EXISTS domains_au AFTER UPDATE ON domains BEGIN
    INSERT INTO domains_fts(domains_fts, rowid, domain) VALUES ('delete', old.id, old.domain);
    INSERT INTO domains_fts(rowid, domain) VALUES (new.id, new.domain);
END;

-- findings
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, title, description, target, cve)
        VALUES (new.id, new.title, new.description, new.target, new.cve);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, target, cve)
        VALUES ('delete', old.id, old.title, old.description, old.target, old.cve);
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, target, cve)
        VALUES ('delete', old.id, old.title, old.description, old.target, old.cve);
    INSERT INTO findings_fts(rowid, title, description, target, cve)
        VALUES (new.id, new.title, new.description, new.target, new.cve);
END;

-- ============================================================================
-- 视图:常用查询封装
-- ============================================================================

-- 任务汇总(含死源统计)
CREATE VIEW IF NOT EXISTS v_task_summary AS
SELECT
    t.id, t.workspace_id, t.name, t.target, t.status,
    t.sources_total, t.sources_ok, t.sources_failed,
    t.started_at, t.finished_at,
    (t.finished_at IS NOT NULL) AS is_finished,
    CAST((julianday(COALESCE(t.finished_at, CURRENT_TIMESTAMP)) - julianday(t.started_at)) * 86400 AS INTEGER) AS duration_seconds
FROM tasks t;

-- 资产汇总(按类型)
CREATE VIEW IF NOT EXISTS v_asset_counts AS
SELECT
    workspace_id,
    (SELECT COUNT(*) FROM domains WHERE workspace_id = w.id) AS domains,
    (SELECT COUNT(*) FROM hosts WHERE workspace_id = w.id) AS hosts,
    (SELECT COUNT(*) FROM ports WHERE workspace_id = w.id) AS ports,
    (SELECT COUNT(*) FROM sites WHERE workspace_id = w.id) AS sites,
    (SELECT COUNT(*) FROM findings WHERE workspace_id = w.id) AS findings
FROM workspaces w;

-- 本周新增资产(给 diff 视图用)
CREATE VIEW IF NOT EXISTS v_assets_new_this_week AS
SELECT 'domain' AS type, workspace_id, hash, domain AS name, first_seen
FROM domains WHERE first_seen >= datetime('now', '-7 days')
UNION ALL
SELECT 'site', workspace_id, hash, url, first_seen
FROM sites WHERE first_seen >= datetime('now', '-7 days')
UNION ALL
SELECT 'port', workspace_id, hash, ip || ':' || port, first_seen
FROM ports WHERE first_seen >= datetime('now', '-7 days');

-- 高危资产(综合 risk + severity)
CREATE VIEW IF NOT EXISTS v_high_risk_assets AS
SELECT 'site' AS type, s.workspace_id, s.url AS identifier, s.risk, s.title, s.first_seen
FROM sites s WHERE s.risk >= 7
UNION ALL
SELECT 'port' AS type, p.workspace_id, p.ip || ':' || p.port, p.risk, p.service, p.first_seen
FROM ports p WHERE p.risk >= 7
UNION ALL
SELECT 'finding' AS type, f.workspace_id, f.target, COALESCE(f.risk, 0) AS risk, f.severity, f.first_seen
FROM findings f WHERE f.severity IN ('high', 'critical') OR f.risk >= 7
ORDER BY risk DESC, first_seen DESC;
