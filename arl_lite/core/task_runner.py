"""arl_lite.core.task_runner

任务运行器:接收一个 target + 一组 modules,串行执行,记录状态。

Phase 1 实现,够用就好,不引入 Celery/Redis。
"""
from __future__ import annotations

import time
import json
import logging
import asyncio
import threading
from datetime import datetime

from .base_module import BaseModule, ModuleResult
from ..db.storage import Storage
from ..modules.registry import discover_modules

log = logging.getLogger("arl_lite.task_runner")


class TaskRunner:
    """任务运行器(单进程版)

    用法:
        storage = Storage(workspace="default")
        runner = TaskRunner(storage=storage, workspace_id=1)
        result = await runner.run(target="example.com", modules=["subfinder", "crtsh"])
    """

    def __init__(self, storage: Storage, workspace_id: int):
        self.storage = storage
        self.workspace_id = workspace_id
        self.current_task_id: int = 0
        self._modules: list[BaseModule] = []
        self._stop_requested = threading.Event()
        self._module_tasks: list[asyncio.Task] = []
        self._event_loop = None

    def mark_stopped(self) -> None:
        """SIGTERM 触发:只置事件,不做 DB 写

        信号处理器里做 SQLite 写会被别的连接的写锁阻塞(Ctrl+C"按了没反应"),
        状态回写挪到 run() 收尾统一处理。
        """
        self._stop_requested.set()
        if self.current_task_id > 0:
            log.info(f"task {self.current_task_id} stop requested (will be marked STOPPED on finalize)")

    def request_stop_all(self) -> None:
        """SIGTERM 触发:通知所有 module 停止"""
        self._stop_requested.set()
        for m in self._modules:
            m.request_stop()
        loop = self._event_loop
        if loop and loop.is_running():
            for task in self._module_tasks:
                loop.call_soon_threadsafe(task.cancel)
        log.debug(f"stop requested for {len(self._modules)} modules")

    def cleanup(self) -> None:
        """atexit 钩子:释放资源"""
        # 当前无资源需要释放,留接口
        log.debug("cleanup done")

    async def run(
        self, target: str, modules: list[str] | None = None,
        preset: str | None = None, config: dict | None = None,
    ) -> ModuleResult:
        """Finalize tasks even when setup, persistence or cancellation aborts."""
        try:
            return await self._run(target, modules, preset, config)
        except BaseException as exc:
            if self.current_task_id:
                status = "STOPPED" if self._stop_requested.is_set() or isinstance(exc, asyncio.CancelledError) else "FAILED"
                self.storage.update_task_status(self.current_task_id, status,
                    finished_at=datetime.utcnow().isoformat(), error_message=type(exc).__name__)
            raise
        finally:
            self.current_task_id = 0
            self._modules = []
            self._module_tasks = []
            self._event_loop = None
            self._stop_requested.clear()

    async def _run(
        self,
        target: str,
        modules: list[str] | None = None,
        preset: str | None = None,
        config: dict | None = None,
    ) -> ModuleResult:
        """跑一个任务(Phase 1:串行)

        Args:
            target: 目标(域名/IP/URL)
            modules: 模块名列表(如 ["subfinder", "crtsh"])
            preset: preset 名(暂未实现,Phase 2)
            config: 模块配置覆盖

        Returns:
            聚合的 ModuleResult
        """
        started = time.time()
        sources_total = len(modules or [])
        sources_ok = 0
        sources_failed = 0
        all_errors: list[str] = []

        # 1. 创建任务记录
        task_id = self.storage.create_task(
            workspace_id=self.workspace_id,
            name=f"scan {target}",
            target=target,
            modules=json.dumps(modules or []),
            config=json.dumps(config or {}),
            sources_total=sources_total,
        )
        self.current_task_id = task_id
        log.info(f"task {task_id} started: target={target} modules={modules}")

        # 2. 标记 RUNNING
        self.storage.update_task_status(
            task_id, "RUNNING", started_at=datetime.utcnow().isoformat()
        )

        # 3. 发现并实例化模块
        available = discover_modules()
        selected = []
        for mod_name in modules or []:
            if mod_name not in available:
                err = f"module '{mod_name}' not found (available: {sorted(available.keys())})"
                log.error(err)
                all_errors.append(err)
                sources_failed += 1
                continue
            mod_cls = available[mod_name]
            # 关键:注入 storage 实例,避免 Module 内部 new
            mod_instance = mod_cls(
                task_id=task_id,
                workspace_id=self.workspace_id,
                config=config,
                storage=self.storage,
            )
            selected.append(mod_instance)

        self._modules = selected

        # 记录每个源的状态(并发前后都会写)
        # 这里预占位,结果在并发后写

        # 4. 并发执行(Phase 2:9 源并行,总时间 = max 而非 sum)
        results: list[ModuleResult] = []
        if not selected:
            log.warning(f"task {task_id} no modules selected")
        else:
            async def _run_one(mod):
                if mod.should_stop():
                    log.warning(f"task {task_id} stopped before {mod.name}")
                    return None
                try:
                    log.info(f"[{mod.name}] running on {target}...")
                    await mod.setup()
                    result = await mod.run(target)
                    log.info(
                        f"[{mod.name}] done: found={result.found} "
                        f"duration={result.duration_seconds:.1f}s errors={len(result.errors)}"
                    )
                    return result
                except asyncio.CancelledError:
                    self.storage.record_source_status(task_id, mod.name, False,
                        error_type="cancelled", error_message="execution stopped")
                    raise
                except Exception as e:
                    log.exception(f"[{mod.name}] crashed: {e}")
                    return ModuleResult(
                        success=False, target=target, found=0,
                        duration_seconds=0, errors=[f"{mod.name} crashed: {e}"],
                    )
                finally:
                    await mod.teardown()

            # asyncio.gather 让所有 module 并发跑
            # return_exceptions=True 防止一个 module 异常杀掉其他
            self._event_loop = asyncio.get_running_loop()
            self._module_tasks = [asyncio.create_task(_run_one(mod)) for mod in selected]
            if self._stop_requested.is_set():
                self.request_stop_all()
            gathered = await asyncio.gather(*self._module_tasks, return_exceptions=True)
            for r in gathered:
                if isinstance(r, BaseException):
                    all_errors.append(f"gather: {type(r).__name__}: {r}")
                    sources_failed += 1
                    continue
                if r is None:
                    continue
                results.append(r)
                for src in r.sources:
                    if src.ok:
                        sources_ok += 1
                    else:
                        sources_failed += 1
                    # 入库 source_status(零假数据纪律)
                    self.storage.record_source_status(
                        task_id=task_id,
                        source_name=src.source,
                        ok=src.ok,
                        found_count=len(src.data),
                        duration_seconds=src.duration,
                        error_type=src.error_type,
                        error_message=src.error,
                    )
                all_errors.extend(r.errors)

        # 5. 收尾
        finished_at = datetime.utcnow().isoformat()
        # SIGTERM:mark_stopped 只置了事件,这里统一回写 STOPPED
        cur_status = self.storage.get_task_status(task_id)
        if cur_status == "RUNNING":
            if self._stop_requested.is_set():
                final_status = "STOPPED"
            elif sources_ok > 0 and sources_failed > 0:
                # 部分成功:与 CLI 的"任一源成功即 exit 0"口径一致,
                # 而 FAILED 专指 0 源成功(cron 看 exit code,人看 task 状态)
                final_status = "DONE_PARTIAL"
            elif sources_ok > 0:
                final_status = "DONE"
            else:
                final_status = "FAILED"
            self.storage.update_task_status(
                task_id, final_status, finished_at=finished_at,
                sources_ok=sources_ok, sources_failed=sources_failed
            )
        else:
            # 已被改过状态(异常路径),补完 sources 统计
            self.storage.update_task_status(
                task_id, cur_status,
                sources_ok=sources_ok, sources_failed=sources_failed
            )

        self.current_task_id = 0
        self._modules = []
        self._stop_requested.clear()

        # 6. 聚合结果
        total_found = sum(r.found for r in results)
        return ModuleResult(
            success=not all_errors,
            target=target,
            found=total_found,
            duration_seconds=time.time() - started,
            sources=[s for r in results for s in r.sources],
            errors=all_errors,
            metadata={"task_id": task_id, "modules_run": len(results)},
        )
