"""
Logging and monitoring module for the sample Python application.
Contains custom logging setup and monitoring functions.
"""

import os
import sys
import logging
import datetime
import traceback
from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Import configuration and utilities
from config import LOG_CONFIG, APP_NAME, APP_VERSION
from utils import get_app_info, format_file_size


@dataclass
class LogEntry:
    """Data class for structured log entries."""
    timestamp: datetime.datetime
    level: str
    module: str
    message: str
    extra_data: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[int] = None
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'module': self.module,
            'message': self.message,
            'extra_data': self.extra_data,
            'user_id': self.user_id,
            'request_id': self.request_id
        }


@dataclass
class PerformanceMetrics:
    """Data class for performance monitoring."""
    operation: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    duration_ms: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def complete(self, success: bool = True, error_message: Optional[str] = None):
        """Mark operation as complete."""
        self.end_time = datetime.datetime.now()
        self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
        self.success = success
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'operation': self.operation,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_ms': self.duration_ms,
            'success': self.success,
            'error_message': self.error_message,
            'metadata': self.metadata
        }


class CustomFormatter(logging.Formatter):
    """Custom formatter for enhanced logging with colors and structured data."""
    
    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, use_colors: bool = True):
        """
        Initialize custom formatter.
        
        Args:
            use_colors (bool): Whether to use colors in console output
        """
        super().__init__()
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with enhanced information.
        
        Args:
            record (logging.LogRecord): Log record to format
            
        Returns:
            str: Formatted log message
        """
        # Create base format
        timestamp = datetime.datetime.fromtimestamp(record.created).isoformat()
        
        # Add color if enabled
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            level_colored = f"{color}{record.levelname}{reset}"
        else:
            level_colored = record.levelname

        # Build formatted message
        base_message = f"{timestamp} | {level_colored:8} | {record.name:20} | {record.getMessage()}"
        
        # Add extra information if available
        extra_info = []
        if hasattr(record, 'user_id') and record.user_id:
            extra_info.append(f"user_id={record.user_id}")
        if hasattr(record, 'request_id') and record.request_id:
            extra_info.append(f"request_id={record.request_id}")
        
        if extra_info:
            base_message += f" | {' | '.join(extra_info)}"
        
        # Add exception information if present
        if record.exc_info:
            base_message += f"\n{self.formatException(record.exc_info)}"
        
        return base_message


class Logger:
    """
    Enhanced logger class with monitoring and structured logging capabilities.
    """
    
    def __init__(self, name: str = APP_NAME):
        """
        Initialize logger.
        
        Args:
            name (str): Logger name
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.performance_metrics: List[PerformanceMetrics] = []
        self.log_entries: List[LogEntry] = []
        self._setup_logger()

    def _setup_logger(self):
        """Set up logger with handlers and formatters."""
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set log level
        log_level = getattr(logging, LOG_CONFIG['level'].upper(), logging.INFO)
        self.logger.setLevel(log_level)
        
        # Create console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_formatter = CustomFormatter(use_colors=True)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Create file handler with rotation
        self._setup_file_handler()
        
        # Prevent propagation to root logger
        self.logger.propagate = False

    def _setup_file_handler(self):
        """Set up rotating file handler."""
        try:
            # Create logs directory if it doesn't exist
            log_file_path = Path(LOG_CONFIG['file_path'])
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create rotating file handler
            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=LOG_CONFIG['max_file_size'],
                backupCount=LOG_CONFIG['backup_count']
            )
            
            file_handler.setLevel(logging.DEBUG)  # File logs everything
            file_formatter = CustomFormatter(use_colors=False)  # No colors in files
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            # If file logging fails, log to console
            self.logger.error(f"Failed to setup file logging: {str(e)}")

    def _create_log_entry(self, level: str, message: str, **kwargs) -> LogEntry:
        """Create structured log entry."""
        entry = LogEntry(
            timestamp=datetime.datetime.now(),
            level=level,
            module=self.name,
            message=message,
            user_id=kwargs.get('user_id'),
            request_id=kwargs.get('request_id'),
            extra_data={k: v for k, v in kwargs.items() if k not in ['user_id', 'request_id']}
        )
        
        # Store entry for monitoring
        self.log_entries.append(entry)
        
        # Keep only recent entries (last 1000)
        if len(self.log_entries) > 1000:
            self.log_entries = self.log_entries[-1000:]
        
        return entry

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        entry = self._create_log_entry('DEBUG', message, **kwargs)
        self.logger.debug(message, extra=entry.extra_data)

    def info(self, message: str, **kwargs):
        """Log info message."""
        entry = self._create_log_entry('INFO', message, **kwargs)
        self.logger.info(message, extra=entry.extra_data)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        entry = self._create_log_entry('WARNING', message, **kwargs)
        self.logger.warning(message, extra=entry.extra_data)

    def error(self, message: str, exception: Optional[Exception] = None, **kwargs):
        """Log error message with optional exception."""
        entry = self._create_log_entry('ERROR', message, **kwargs)
        
        if exception:
            entry.extra_data['exception_type'] = type(exception).__name__
            entry.extra_data['exception_message'] = str(exception)
            self.logger.error(message, exc_info=exception, extra=entry.extra_data)
        else:
            self.logger.error(message, extra=entry.extra_data)

    def critical(self, message: str, exception: Optional[Exception] = None, **kwargs):
        """Log critical message with optional exception."""
        entry = self._create_log_entry('CRITICAL', message, **kwargs)
        
        if exception:
            entry.extra_data['exception_type'] = type(exception).__name__
            entry.extra_data['exception_message'] = str(exception)
            self.logger.critical(message, exc_info=exception, extra=entry.extra_data)
        else:
            self.logger.critical(message, extra=entry.extra_data)

    def performance(self, operation: str, **metadata) -> PerformanceMetrics:
        """
        Start performance monitoring for an operation.
        
        Args:
            operation (str): Operation name
            **metadata: Additional metadata
            
        Returns:
            PerformanceMetrics: Performance metrics object
        """
        metrics = PerformanceMetrics(
            operation=operation,
            start_time=datetime.datetime.now(),
            metadata=metadata
        )
        
        self.performance_metrics.append(metrics)
        self.debug(f"Started operation: {operation}", **metadata)
        
        return metrics

    def get_recent_logs(self, count: int = 100, level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent log entries.
        
        Args:
            count (int): Number of entries to return
            level (Optional[str]): Filter by log level
            
        Returns:
            List[Dict[str, Any]]: Recent log entries
        """
        entries = self.log_entries
        
        if level:
            entries = [entry for entry in entries if entry.level == level.upper()]
        
        return [entry.to_dict() for entry in entries[-count:]]

    def get_performance_summary(self, minutes: int = 60) -> Dict[str, Any]:
        """
        Get performance summary for the specified time period.
        
        Args:
            minutes (int): Time period in minutes
            
        Returns:
            Dict[str, Any]: Performance summary
        """
        cutoff_time = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
        recent_metrics = [
            m for m in self.performance_metrics 
            if m.start_time > cutoff_time and m.end_time
        ]
        
        if not recent_metrics:
            return {
                'time_period_minutes': minutes,
                'total_operations': 0,
                'successful_operations': 0,
                'failed_operations': 0,
                'average_duration_ms': 0,
                'slowest_operation': None,
                'fastest_operation': None
            }
        
        successful_ops = [m for m in recent_metrics if m.success]
        failed_ops = [m for m in recent_metrics if not m.success]
        
        durations = [m.duration_ms for m in recent_metrics if m.duration_ms]
        
        slowest = max(recent_metrics, key=lambda x: x.duration_ms or 0)
        fastest = min(recent_metrics, key=lambda x: x.duration_ms or float('inf'))
        
        return {
            'time_period_minutes': minutes,
            'total_operations': len(recent_metrics),
            'successful_operations': len(successful_ops),
            'failed_operations': len(failed_ops),
            'average_duration_ms': sum(durations) / len(durations) if durations else 0,
            'slowest_operation': {
                'operation': slowest.operation,
                'duration_ms': slowest.duration_ms
            } if slowest.duration_ms else None,
            'fastest_operation': {
                'operation': fastest.operation,
                'duration_ms': fastest.duration_ms
            } if fastest.duration_ms != float('inf') else None
        }


def performance_monitor(operation_name: Optional[str] = None):
    """
    Decorator for automatic performance monitoring.
    
    Args:
        operation_name (Optional[str]): Custom operation name
        
    Returns:
        Callable: Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get logger instance (assuming first arg is self with logger)
            logger_instance = None
            if args and hasattr(args[0], 'logger') and isinstance(args[0].logger, Logger):
                logger_instance = args[0].logger
            else:
                # Fallback to global logger
                logger_instance = Logger(func.__module__)
            
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            metrics = logger_instance.performance(op_name)
            
            try:
                result = func(*args, **kwargs)
                metrics.complete(success=True)
                logger_instance.debug(f"Completed operation: {op_name}", duration_ms=metrics.duration_ms)
                return result
            
            except Exception as e:
                metrics.complete(success=False, error_message=str(e))
                logger_instance.error(f"Failed operation: {op_name}", exception=e, duration_ms=metrics.duration_ms)
                raise
        
        return wrapper
    return decorator


class SystemMonitor:
    """System monitoring and health check utilities."""
    
    def __init__(self, logger: Logger):
        """
        Initialize system monitor.
        
        Args:
            logger (Logger): Logger instance
        """
        self.logger = logger

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get comprehensive system health information.
        
        Returns:
            Dict[str, Any]: System health data
        """
        try:
            # Get application info
            app_info = get_app_info()
            
            # Get log file information
            log_file_info = self._get_log_file_info()
            
            # Get recent error count
            recent_errors = len(self.logger.get_recent_logs(count=1000, level='ERROR'))
            recent_warnings = len(self.logger.get_recent_logs(count=1000, level='WARNING'))
            
            # Get performance summary
            perf_summary = self.logger.get_performance_summary(minutes=30)
            
            return {
                'status': 'healthy',  # Would be calculated based on metrics
                'application': app_info,
                'logging': {
                    'file_info': log_file_info,
                    'recent_errors': recent_errors,
                    'recent_warnings': recent_warnings,
                    'total_log_entries': len(self.logger.log_entries)
                },
                'performance': perf_summary,
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        except Exception as e:
            self.logger.error("Failed to get system health", exception=e)
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            }

    def _get_log_file_info(self) -> Dict[str, Any]:
        """Get log file information."""
        try:
            log_file_path = Path(LOG_CONFIG['file_path'])
            
            if log_file_path.exists():
                stat = log_file_path.stat()
                return {
                    'path': str(log_file_path),
                    'size': format_file_size(stat.st_size),
                    'size_bytes': stat.st_size,
                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'max_size': format_file_size(LOG_CONFIG['max_file_size']),
                    'backup_count': LOG_CONFIG['backup_count']
                }
            else:
                return {
                    'path': str(log_file_path),
                    'exists': False
                }
        
        except Exception as e:
            return {
                'error': str(e)
            }

    def alert_on_errors(self, error_threshold: int = 10, time_window_minutes: int = 5) -> bool:
        """
        Check if error rate exceeds threshold.
        
        Args:
            error_threshold (int): Maximum allowed errors
            time_window_minutes (int): Time window in minutes
            
        Returns:
            bool: True if alert should be triggered
        """
        cutoff_time = datetime.datetime.now() - datetime.timedelta(minutes=time_window_minutes)
        recent_errors = [
            entry for entry in self.logger.log_entries
            if entry.timestamp > cutoff_time and entry.level in ['ERROR', 'CRITICAL']
        ]
        
        if len(recent_errors) >= error_threshold:
            self.logger.critical(
                f"High error rate detected: {len(recent_errors)} errors in {time_window_minutes} minutes",
                error_count=len(recent_errors),
                threshold=error_threshold,
                time_window=time_window_minutes
            )
            return True
        
        return False


# Global logger instance
app_logger = Logger(APP_NAME)

# Export main classes and functions
__all__ = [
    'LogEntry', 'PerformanceMetrics', 'CustomFormatter', 'Logger',
    'performance_monitor', 'SystemMonitor', 'app_logger'
]