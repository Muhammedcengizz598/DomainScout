"""
DomainScout Pro - Logging Module
Comprehensive logging for all operations
"""
import logging
import datetime
from pathlib import Path
import json
from typing import Any, Dict, Optional


class DomainScoutLogger:
    """Advanced logging system for DomainScout Pro"""
    
    def __init__(self, log_dir: Optional[str] = None):
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            self.log_dir = Path(__file__).parent / "logs"
        
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup loggers
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup different loggers for different purposes"""
        
        # Main application logger
        self.app_logger = self._create_logger(
            'domainscout_app',
            self.log_dir / 'application.log'
        )
        
        # Analysis logger
        self.analysis_logger = self._create_logger(
            'domainscout_analysis',
            self.log_dir / 'analysis.log'
        )
        
        # Error logger
        self.error_logger = self._create_logger(
            'domainscout_errors',
            self.log_dir / 'errors.log',
            level=logging.ERROR
        )
        
        # Export logger
        self.export_logger = self._create_logger(
            'domainscout_export',
            self.log_dir / 'exports.log'
        )
    
    def _create_logger(self, name: str, log_file: Path, level=logging.INFO):
        """Create a logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Clear existing handlers
        logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_app_event(self, message: str, level: str = 'info'):
        """Log application event"""
        if level == 'info':
            self.app_logger.info(message)
        elif level == 'warning':
            self.app_logger.warning(message)
        elif level == 'error':
            self.app_logger.error(message)
        elif level == 'debug':
            self.app_logger.debug(message)
    
    def log_analysis_start(self, domain: str):
        """Log analysis start"""
        self.analysis_logger.info(f"Starting analysis for domain: {domain}")
    
    def log_analysis_complete(self, domain: str, duration: float):
        """Log analysis completion"""
        self.analysis_logger.info(
            f"Analysis completed for {domain} in {duration:.2f} seconds"
        )
    
    def log_analysis_task(self, domain: str, task: str, status: str):
        """Log individual analysis task"""
        self.analysis_logger.info(f"{domain} - {task}: {status}")
    
    def log_error(self, error: Exception, context: Optional[str] = None):
        """Log error with context"""
        error_msg = f"Error: {str(error)}"
        if context:
            error_msg = f"{context} - {error_msg}"
        
        self.error_logger.error(error_msg, exc_info=True)
    
    def log_export(self, domain: str, format_type: str, filepath: str):
        """Log export operation"""
        self.export_logger.info(
            f"Exported {domain} data to {format_type} format: {filepath}"
        )
    
    def create_analysis_report(self, domain: str, results: Dict[str, Any]):
        """Create detailed analysis log report"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.log_dir / f"analysis_report_{domain}_{timestamp}.json"
        
        report = {
            'domain': domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': {
                'analysis_complete': results.get('analysis_complete', False),
                'risk_score': results.get('risk_score', {}).get('score', 0),
                'risk_rating': results.get('risk_score', {}).get('rating', 'Unknown'),
                'total_issues': results.get('risk_score', {}).get('total_issues', 0)
            },
            'modules_executed': list(results.keys())
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.analysis_logger.info(f"Analysis report saved: {report_file}")
        
        return str(report_file)


# Global logger instance
_logger_instance = None

def get_logger():
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = DomainScoutLogger()
    return _logger_instance
