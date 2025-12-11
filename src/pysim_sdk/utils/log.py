import logging
import multiprocessing
import threading

import structlog


class PysimObserver:
    def __init__(self, pysim):
        self.pysim = pysim
        self.renderer = structlog.processors.JSONRenderer()

    def __call__(self, logger, name, events):
        self.pysim.log(self.renderer(logger, name, events))
        return events


def configure(pysim):
    structlog.configure(
        processors=[
            PysimObserver(pysim),
            _add_process_name,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.format_exc_info,
            structlog.processors.TimeStamper(fmt="%H:%M:%S.%f", utc=False),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.NOTSET),
        context_class=dict,
        cache_logger_on_first_use=False,
    )


def _add_process_name(_, __, events):
    events["name"] = multiprocessing.current_process().name
    return events


def _logger():
    return structlog.get_logger(threading.current_thread().name)


def info(*args, **kwargs):
    _logger().info(*args, **kwargs)


def warn(*args, **kwargs):
    _logger().warn(*args, **kwargs)


def error(*args, **kwargs):
    _logger().error(*args, **kwargs)
