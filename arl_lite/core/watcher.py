"""arl_lite.core.watcher

Watch 模式 — 持续监控目标,新发现/变化时告警。

设计:
- 定期重跑 target(默认 24h,可配)
- 跟踪 last_run + new_assets count
- 新发现 critical / 资产变化触发 webhook
- 纯 stdlib(threading.Event + time)
- SIGTERM 优雅退出
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime

log = logging.getLogger("arl_lite.core.watcher")


class WatchTarget:
    """单个 watch 目标

    Attributes:
        target: 域名/IP/URL
        modules: 跑哪些 module
        interval_seconds: 重跑间隔秒
        last_run: 上次跑时间戳
        next_run: 下次跑时间戳
        last_count: 上次资产数
        run_count: 总跑次数
        new_count: 新资产数(累计)
    """
    def __init__(
        self,
        target: str,
        modules: list[str] | None = None,
        interval_seconds: int = 86400,  # 24h
    ):
        if not isinstance(target, str) or not target.strip():
            raise ValueError("watch target must be non-empty str")
        if len(target) > 1000:
            raise ValueError("watch target too long")
        self.target = target.strip()
        self.modules = modules or ["dns", "whois", "subfinder", "crtsh"]
        if not isinstance(self.modules, list):
            raise ValueError("modules must be list")
        if not isinstance(interval_seconds, int) or interval_seconds < 60:
            raise ValueError(f"interval_seconds must be int >= 60, got {interval_seconds}")
        self.interval_seconds = interval_seconds
        self.last_run: str | None = None
        self.next_run: str | None = None
        self.last_count: int = 0
        self.run_count: int = 0
        self.new_count: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "modules": self.modules,
            "interval_seconds": self.interval_seconds,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "last_count": self.last_count,
            "run_count": self.run_count,
            "new_count": self.new_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WatchTarget":
        wt = cls(
            target=d["target"],
            modules=d.get("modules"),
            interval_seconds=d.get("interval_seconds", 86400),
        )
        wt.last_run = d.get("last_run")
        wt.next_run = d.get("next_run")
        wt.last_count = d.get("last_count", 0)
        wt.run_count = d.get("run_count", 0)
        wt.new_count = d.get("new_count", 0)
        return wt


class Watcher:
    """Watch 调度器

    Usage:
        w = Watcher(storage, webhook_config=...)
        w.add("example.com", modules=["dns", "whois"], interval=3600)
        w.add("foo.com", interval=7200)
        w.start()  # 后台线程循环
        # ...
        w.stop()

    工作流:
    - 每个 target 独立调度(独立 interval)
    - 跑完调 WebhookConfig 通知
    - SIGTERM / stop() 优雅退出
    """

    def __init__(self, storage, webhook_config=None, on_run=None):
        self.storage = storage
        self.webhook = webhook_config
        self.on_run = on_run  # 可选 callback(target, found, duration, new_count)
        self._targets: dict[str, WatchTarget] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def add(self, target: str, modules=None, interval_seconds: int = 86400) -> WatchTarget:
        """添加 watch target"""
        wt = WatchTarget(target, modules, interval_seconds)
        with self._lock:
            self._targets[target] = wt
        log.info(f"watch: added target={target} modules={wt.modules} interval={wt.interval_seconds}s")
        return wt

    def remove(self, target: str) -> bool:
        with self._lock:
            if target in self._targets:
                del self._targets[target]
                log.info(f"watch: removed target={target}")
                return True
        return False

    def list(self) -> list[WatchTarget]:
        with self._lock:
            return list(self._targets.values())

    def start(self) -> None:
        """启动后台 watch 线程"""
        if self._thread and self._thread.is_alive():
            log.warning("watch: already running")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="watcher", daemon=True)
        self._thread.start()
        log.info(f"watch: started with {len(self._targets)} targets")

    def stop(self, timeout: float = 5.0) -> None:
        """优雅停止

        join 前先向正在跑的扫描传播停止(光 set _stop 要等当前目标整个
        扫完);join 超时说明扫描还没退出,如实告警而不是谎报已停止
        (daemon 线程随后被强杀会留下 RUNNING 任务孤儿)。
        """
        self.request_stop_all()
        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning(f"watch: thread still running after {timeout}s stop (scan will be killed on exit)")
            else:
                log.info("watch: stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ---- GracefulShutdown duck-typing 接口 ----
    # cli.cmd_watch_start 把 Watcher 传给 GracefulShutdown,信号处理器会依次调用
    # mark_stopped / request_stop_all / cleanup。缺了任何一个,第一次 SIGTERM/Ctrl+C
    # 就会被吞掉(AttributeError 被 except 吃掉),要按第二次才强制退出。

    def mark_stopped(self) -> None:
        """信号处理:watch 无任务状态可回写,仅留痕"""
        log.info("watch: shutdown requested (mark_stopped)")

    def request_stop_all(self) -> None:
        """信号处理:置停止事件,并通知当前正在跑的 TaskRunner 停止

        只 set _stop 的话,循环要等当前目标整个扫描完才会检查,一次
        Ctrl+C 就"按了没反应"。把停止传播到 runner 内的 modules,
        长扫描也能协作式退出。
        """
        self._stop.set()
        runner = getattr(self, "_current_runner", None)
        if runner is not None:
            try:
                runner.request_stop_all()
                runner.mark_stopped()
            except Exception as e:
                log.debug(f"watch: stop runner failed: {e}")

    def cleanup(self) -> None:
        """atexit 钩子:watch 无额外资源需要释放"""
        pass

    def _loop(self) -> None:
        """主循环:等 target 到期,跑

        lock 内只做到期判定和快照,真正扫描在 lock 外执行——否则一次
        几分钟的网络扫描会让 add/remove/list/status 全部卡死。
        """
        while not self._stop.is_set():
            now = time.time()
            next_wake = None
            due: list[WatchTarget] = []
            with self._lock:
                for wt in self._targets.values():
                    next_at = self._next_run_at(wt)
                    if next_at is None:
                        continue
                    if next_at <= now:
                        due.append(wt)
                    if next_wake is None or next_at < next_wake:
                        next_wake = next_at
            for wt in due:
                if self._stop.is_set():
                    break
                try:
                    self._run_target(wt)
                except Exception as e:
                    log.exception(f"watch: run failed for {wt.target}: {e}")
                wt.next_run = datetime.fromtimestamp(
                    time.time() + wt.interval_seconds
                ).isoformat()
            # sleep 到下次(或 stop)
            if next_wake is None:
                wait = 60.0  # 没目标时 60s 醒一次
            else:
                wait = max(1.0, min(60.0, next_wake - time.time()))
            self._stop.wait(timeout=wait)

    def _next_run_at(self, wt: WatchTarget) -> float | None:
        if wt.next_run:
            try:
                return datetime.fromisoformat(wt.next_run).timestamp()
            except Exception:
                pass
        # 没 next_run:立即跑一次
        return time.time() - 1

    def _run_target(self, wt: WatchTarget) -> None:
        """跑一个 target(同步)— 包含变化检测 + monitor 变更接线"""
        from ..core.task_runner import TaskRunner  # 延迟 import 避免循环
        from ..core.monitor import Monitor
        from ..notify import notify_task_done, notify_critical_finding

        start = time.time()
        log.info(f"watch: running target={wt.target} modules={wt.modules}")

        runner = TaskRunner(
            storage=self.storage,
            workspace_id=self.storage.workspace_id,
        )
        self._current_runner = runner  # request_stop_all 时传播停止
        try:
            # TaskRunner.run 是 async — 在新 event loop 跑
            import asyncio
            result = asyncio.run(
                runner.run(
                    target=wt.target,
                    modules=wt.modules,
                )
            )
        except Exception as e:
            log.exception(f"watch: TaskRunner failed for {wt.target}: {e}")
            return
        finally:
            self._current_runner = None

        task_id = result.metadata.get("task_id")
        if not task_id:
            log.warning("watch: runner returned no task_id; cannot attribute changes")
            return
        changes = self.storage.get_run_changes(task_id)
        new_by_type = {t: sum(c["asset_type"] == t and c["change_type"] == "NEW_ASSET" for c in changes)
                       for t in ("host", "domain", "port", "site", "finding")}
        new_total = sum(new_by_type.values())

        # 更新 target 状态
        wt.last_run = datetime.utcnow().isoformat()
        wt.next_run = datetime.fromtimestamp(
            time.time() + wt.interval_seconds
        ).isoformat()
        wt.last_count = len(self.storage.get_run_observations(task_id))
        wt.run_count += 1
        wt.new_count += new_total

        duration = time.time() - start
        log.info(
            f"watch: target={wt.target} done in {duration:.1f}s, "
            f"new={new_total} "
            f"changes={len(changes)}"
        )

        # Changes are recorded atomically by storage and attributed by run,
        # including fields changed on an existing asset.
        critical_findings: list[dict] = []
        import json
        for change in changes:
            if change["asset_type"] != "finding":
                continue
            after = json.loads(change["after_value"] or "{}")
            before = json.loads(change["before_value"] or "{}")
            if after.get("severity") == "critical" and before.get("severity") != "critical":
                critical_findings.append(after)

        # 同步 monitors 表状态(如果有对该 target 的监控)
        try:
            for m in Monitor(self.storage).list():
                if m.get("target") == wt.target:
                    Monitor(self.storage).record_run(m["id"], len(changes))
        except Exception as e:
            log.debug(f"watch: monitor record_run failed: {e}")

        # 通知
        if self.webhook:
            notify_task_done(
                self.webhook,
                task_id=task_id,
                target=wt.target,
                found=new_total,
                duration_seconds=duration,
            )
            # critical finding 单独通知(只看本次新增的,旧版会拿错行)
            for f in critical_findings:
                notify_critical_finding(self.webhook, f)

        # 外部 callback
        if self.on_run:
            try:
                self.on_run(wt.target, new_total, duration, new_total)
            except Exception as e:
                log.exception(f"watch: on_run callback failed: {e}")

    def _count_assets(self) -> dict[str, int]:
        try:
            return self.storage.get_stats()
        except Exception:
            return {}

    def status(self) -> dict:
        return {
            "running": self.is_running(),
            "targets": [wt.to_dict() for wt in self.list()],
        }
