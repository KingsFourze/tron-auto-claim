import enum
from datetime import datetime

class LogLevel(enum.Enum):
    INFO = 1
    WARNING = 2
    ERROR = 3

def log(message: str, level: LogLevel = LogLevel.INFO):
    prefix = {
        LogLevel.INFO: "[INFO]",
        LogLevel.WARNING: "[WARNING]",
        LogLevel.ERROR: "[ERROR]"
    }.get(level, "[INFO]")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}][{prefix}] {message}", flush=True)