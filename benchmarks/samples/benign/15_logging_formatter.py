"""Custom log formatter for standard logging module."""
import logging

class StructuredLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] [{record.levelname:<8}] {record.name}: {record.getMessage()}"
