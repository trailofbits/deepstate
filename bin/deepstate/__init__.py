import os
import functools
import logging
from sys import exit


class DeepStateLogger(logging.getLoggerClass()): # type: ignore
    def __init__(self, name: str) -> None:
        logging.Logger.__init__(self, name=name)
        self.trace = functools.partial(self.log, 15) # type: ignore
        self.external = functools.partial(self.log, 45) # type: ignore


logging.basicConfig()
logging.addLevelName(15, "TRACE")
logging.addLevelName(45, "EXTERNAL")
logging.setLoggerClass(DeepStateLogger)

logger = logging.getLogger(__name__)

LOG_LEVEL_DEBUG = 0
LOG_LEVEL_TRACE = 1
LOG_LEVEL_INFO = 2
LOG_LEVEL_WARNING = 3
LOG_LEVEL_ERROR = 4
LOG_LEVEL_EXTERNAL = 5
LOG_LEVEL_CRITICAL = 6

LOG_LEVEL_INT_TO_STR = {
  LOG_LEVEL_DEBUG: logging.DEBUG,
  LOG_LEVEL_TRACE: logging.getLevelName(15),
  LOG_LEVEL_INFO: logging.INFO,
  LOG_LEVEL_WARNING: logging.WARNING,
  LOG_LEVEL_ERROR: logging.ERROR,
  LOG_LEVEL_EXTERNAL: logging.getLevelName(45),
  LOG_LEVEL_CRITICAL: logging.CRITICAL
}

LOG_LEVEL_INT_TO_LOGGER = {
  LOG_LEVEL_DEBUG: logger.debug,
  LOG_LEVEL_TRACE: logger.trace, # type: ignore
  LOG_LEVEL_INFO: logger.info,
  LOG_LEVEL_WARNING: logger.warning,
  LOG_LEVEL_ERROR: logger.error,
  LOG_LEVEL_EXTERNAL: logger.external, # type: ignore
  LOG_LEVEL_CRITICAL: logger.critical
}

log_level_from_env: str = os.environ.get("DEEPSTATE_LOG", "2")
try:
  logger.setLevel(LOG_LEVEL_INT_TO_STR[int(log_level_from_env)])
except ValueError:
  print("$DEEPSTATE_LOG contains invalid value `%s`, "
        "should be int in 0-6 (debug, trace, info, warning, error, external, critical).",
        log_level_from_env)
  exit(1)
except KeyError:
  print("$DEEPSTATE_LOG is in invalid range, should be in 0-6 "
        "(debug, trace, info, warning, error, external, critical).")
  exit(1)

__all__ = ["DeepStateLogger", "LOG_LEVEL_INT_TO_STR", "LOG_LEVEL_INT_TO_LOGGER", "LOG_LEVEL_DEBUG",
            "LOG_LEVEL_TRACE", "LOG_LEVEL_INFO", "LOG_LEVEL_WARNING",
            "LOG_LEVEL_ERROR", "LOG_LEVEL_EXTERNAL", "LOG_LEVEL_CRITICAL"]
