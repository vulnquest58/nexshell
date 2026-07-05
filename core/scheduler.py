#!/usr/bin/env python3
"""
NexShell — Task Scheduler  (core/scheduler.py)
Queue-based background task system: Queue → Priority → Completed → Failed.

Usage:
    from core.scheduler import scheduler

    # Schedule a background task
    task_id = scheduler.add(my_fn, args=[session, 'quickenum'], priority=5,
                            label="QuickEnum on 10.0.0.1")
    scheduler.start()

    # Check status
    print(scheduler.status())
"""

import uuid
import time
import queue
import logging
import threading
import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger('nexshell.scheduler')


# ══════════════════════════════════════════════════════════════════════════════
#  TASK
# ══════════════════════════════════════════════════════════════════════════════

class Task:
    """A unit of schedulable work."""

    PENDING   = 'pending'
    RUNNING   = 'running'
    COMPLETED = 'completed'
    FAILED    = 'failed'
    CANCELLED = 'cancelled'

    def __init__(self, fn: Callable, args: list = None, kwargs: dict = None,
                 priority: int = 5, label: str = ""):
        self.id        = str(uuid.uuid4())[:8]
        self.fn        = fn
        self.args      = args or []
        self.kwargs    = kwargs or {}
        self.priority  = priority        # 1 (highest) → 10 (lowest)
        self.label     = label or getattr(fn, '__name__', 'task')
        self.status    = self.PENDING
        self.result    = None
        self.error     = None
        self.created   = datetime.datetime.utcnow().isoformat()
        self.started   = None
        self.finished  = None

    def __lt__(self, other):
        return self.priority < other.priority

    def to_dict(self) -> dict:
        return {
            'id':       self.id,
            'label':    self.label,
            'status':   self.status,
            'priority': self.priority,
            'created':  self.created,
            'started':  self.started,
            'finished': self.finished,
            'error':    str(self.error) if self.error else None,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  TASK SCHEDULER
# ══════════════════════════════════════════════════════════════════════════════

class TaskScheduler:
    """
    Priority queue-based background task runner.
    Tasks execute in order of priority (1 = highest).
    """

    def __init__(self, workers: int = 2):
        self._queue:      queue.PriorityQueue = queue.PriorityQueue()
        self._pending:    Dict[str, Task]     = {}
        self._completed:  List[Task]          = []
        self._failed:     List[Task]          = []
        self._cancelled:  set                 = set()
        self._lock        = threading.RLock()
        self._workers     = workers
        self._threads:    List[threading.Thread] = []
        self._running     = False

    def start(self):
        """Start worker threads."""
        if self._running:
            return
        self._running = True
        for i in range(self._workers):
            t = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name=f'nxsh-scheduler-{i}'
            )
            t.start()
            self._threads.append(t)
        logger.info(f"Task scheduler started ({self._workers} workers)")

    def stop(self):
        self._running = False

    def add(self, fn: Callable, args: list = None, kwargs: dict = None,
            priority: int = 5, label: str = "") -> str:
        """Add a task to the queue. Returns task ID."""
        task = Task(fn, args, kwargs, priority, label)
        with self._lock:
            self._pending[task.id] = task
        self._queue.put((priority, task))
        logger.info(f"Task queued [{task.id}] '{task.label}' (priority={priority})")
        return task.id

    def cancel(self, task_id: str) -> bool:
        """Cancel a pending task. Running tasks cannot be cancelled."""
        with self._lock:
            task = self._pending.get(task_id)
            if task and task.status == Task.PENDING:
                task.status = Task.CANCELLED
                self._cancelled.add(task_id)
                logger.info(f"Task cancelled [{task_id}]")
                return True
        return False

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            if task_id in self._pending:
                return self._pending[task_id]
            for t in self._completed + self._failed:
                if t.id == task_id:
                    return t
        return None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            pending = [t for t in self._pending.values() if t.status == Task.PENDING]
            running = [t for t in self._pending.values() if t.status == Task.RUNNING]
            return {
                'pending':   [t.to_dict() for t in pending],
                'running':   [t.to_dict() for t in running],
                'completed': [t.to_dict() for t in self._completed[-20:]],
                'failed':    [t.to_dict() for t in self._failed[-20:]],
            }

    def _worker_loop(self):
        while self._running:
            try:
                _, task = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if task.id in self._cancelled:
                self._queue.task_done()
                continue

            task.status  = Task.RUNNING
            task.started = datetime.datetime.utcnow().isoformat()
            logger.info(f"Task started [{task.id}] '{task.label}'")

            try:
                task.result  = task.fn(*task.args, **task.kwargs)
                task.status  = Task.COMPLETED
                with self._lock:
                    self._completed.append(task)
                    self._completed = self._completed[-100:]
                logger.info(f"Task completed [{task.id}] '{task.label}'")
            except Exception as e:
                task.status  = Task.FAILED
                task.error   = e
                with self._lock:
                    self._failed.append(task)
                    self._failed = self._failed[-50:]
                logger.warning(f"Task failed [{task.id}] '{task.label}': {e}")
            finally:
                task.finished = datetime.datetime.utcnow().isoformat()
                with self._lock:
                    self._pending.pop(task.id, None)
                self._queue.task_done()

                # Emit event
                try:
                    from core.event_bus import bus
                    bus.emit(
                        f'task.{task.status}',
                        task_id=task.id, label=task.label,
                        error=str(task.error) if task.error else None,
                    )
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

scheduler = TaskScheduler(workers=2)
