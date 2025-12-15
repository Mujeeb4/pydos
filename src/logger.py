
import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional
import json


class DDoSLogger:
    """
    Centralized logging system for DDoS detection and mitigation.
    
    Provides separate log files for:
    - Main events (ddos_events.log)
    - Attack details (ddos_attacks.log)
    - System operations (ddos_system.log)
    """
    
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize the logging system.
        
        Args:
            log_dir (str): Directory to store log files
        """
        self.log_dir = log_dir
        self._ensure_log_directory()
        
        # Create separate loggers
        self.event_logger = self._create_logger(
            "event_logger",
            os.path.join(log_dir, "ddos_events.log")
        )
        self.attack_logger = self._create_logger(
            "attack_logger",
            os.path.join(log_dir, "ddos_attacks.log")
        )
        self.system_logger = self._create_logger(
            "system_logger",
            os.path.join(log_dir, "ddos_system.log")
        )
        
        # Also create a JSON logger for structured data
        self.json_log_path = os.path.join(log_dir, "ddos_events.json")
        
        self._log_startup()
    
    def _ensure_log_directory(self):
        """Create log directory if it doesn't exist"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"[LOGGER] Created log directory: {self.log_dir}")
    
    def _create_logger(self, name: str, log_file: str) -> logging.Logger:
        """
        Create a logger with file rotation.
        
        Args:
            name (str): Logger name
            log_file (str): Path to log file
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # Create rotating file handler (max 5MB per file, keep 5 backups)
        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=5,
            encoding='utf-8'
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
        
        return logger
    
    def _log_startup(self):
        """Log system startup"""
        self.system_logger.info("="*60)
        self.system_logger.info("DDoS Detection System Started")
        self.system_logger.info(f"Log Directory: {self.log_dir}")
        self.system_logger.info("="*60)
    
    def log_system_event(self, message: str, level: str = "INFO"):
        """
        Log a system event.
        
        Args:
            message (str): Event message
            level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        level = level.upper()
        if level == "DEBUG":
            self.system_logger.debug(message)
        elif level == "INFO":
            self.system_logger.info(message)
        elif level == "WARNING":
            self.system_logger.warning(message)
        elif level == "ERROR":
            self.system_logger.error(message)
        elif level == "CRITICAL":
            self.system_logger.critical(message)
    
    def log_attack_detected(self, 
                           ip_address: str, 
                           attack_type: str, 
                           threshold: int, 
                           current_count: int,
                           additional_info: Optional[dict] = None):
        """
        Log an attack detection event.
        
        Args:
            ip_address (str): Source IP of the attack
            attack_type (str): Type of attack (SYN_FLOOD, PACKET_FLOOD, etc.)
            threshold (int): Configured threshold
            current_count (int): Current count that triggered the alert
            additional_info (dict): Additional attack details
        """
        message = (
            f"ATTACK DETECTED | "
            f"Type: {attack_type} | "
            f"Source IP: {ip_address} | "
            f"Count: {current_count}/{threshold}"
        )
        
        if additional_info:
            message += f" | Details: {additional_info}"
        
        self.attack_logger.warning(message)
        self.event_logger.warning(message)
        
        # Also log to JSON file for structured analysis
        self._log_to_json({
            "timestamp": datetime.now().isoformat(),
            "event_type": "attack_detected",
            "attack_type": attack_type,
            "source_ip": ip_address,
            "threshold": threshold,
            "current_count": current_count,
            "additional_info": additional_info or {}
        })
    
    def log_ip_blocked(self, ip_address: str, reason: str, success: bool = True):
        """
        Log an IP blocking action.
        
        Args:
            ip_address (str): IP address that was blocked
            reason (str): Reason for blocking
            success (bool): Whether blocking was successful
        """
        status = "SUCCESS" if success else "FAILED"
        message = f"IP BLOCK {status} | IP: {ip_address} | Reason: {reason}"
        
        if success:
            self.event_logger.warning(message)
            self.attack_logger.warning(message)
        else:
            self.event_logger.error(message)
            self.attack_logger.error(message)
        
        # Log to JSON
        self._log_to_json({
            "timestamp": datetime.now().isoformat(),
            "event_type": "ip_blocked",
            "ip_address": ip_address,
            "reason": reason,
            "success": success
        })
    
    def log_ip_unblocked(self, ip_address: str, success: bool = True):
        """
        Log an IP unblocking action.
        
        Args:
            ip_address (str): IP address that was unblocked
            success (bool): Whether unblocking was successful
        """
        status = "SUCCESS" if success else "FAILED"
        message = f"IP UNBLOCK {status} | IP: {ip_address}"
        
        self.event_logger.info(message)
        
        # Log to JSON
        self._log_to_json({
            "timestamp": datetime.now().isoformat(),
            "event_type": "ip_unblocked",
            "ip_address": ip_address,
            "success": success
        })
    
    def log_traffic_summary(self, summary_data: dict):
        """
        Log traffic summary statistics.
        
        Args:
            summary_data (dict): Dictionary containing traffic statistics
        """
        message = f"TRAFFIC SUMMARY | {json.dumps(summary_data)}"
        self.event_logger.info(message)
        
        # Log to JSON
        self._log_to_json({
            "timestamp": datetime.now().isoformat(),
            "event_type": "traffic_summary",
            "data": summary_data
        })
    
    def log_threshold_config(self, packet_threshold: int, syn_threshold: int, time_window: float, udp_threshold: int = None):
        """
        Log threshold configuration.
        
        Args:
            packet_threshold (int): Packet threshold
            syn_threshold (int): SYN threshold
            time_window (float): Time window in seconds
            udp_threshold (int): UDP threshold (optional)
        """
        if udp_threshold is not None:
            message = (
                f"CONFIGURATION | "
                f"Packet Threshold: {packet_threshold} | "
                f"SYN Threshold: {syn_threshold} | "
                f"UDP Threshold: {udp_threshold} | "
                f"Time Window: {time_window}s"
            )
        else:
            message = (
                f"CONFIGURATION | "
                f"Packet Threshold: {packet_threshold} | "
                f"SYN Threshold: {syn_threshold} | "
                f"Time Window: {time_window}s"
            )
        self.system_logger.info(message)
    
    def log_error(self, error_message: str, exception: Optional[Exception] = None):
        """
        Log an error with optional exception details.
        
        Args:
            error_message (str): Error description
            exception (Exception): Exception object if available
        """
        if exception:
            message = f"ERROR | {error_message} | Exception: {str(exception)}"
            self.system_logger.error(message, exc_info=True)
        else:
            message = f"ERROR | {error_message}"
            self.system_logger.error(message)
        
        # Log to JSON
        self._log_to_json({
            "timestamp": datetime.now().isoformat(),
            "event_type": "error",
            "message": error_message,
            "exception": str(exception) if exception else None
        })
    
    def _log_to_json(self, data: dict):
        """
        Append structured data to JSON log file.
        
        Args:
            data (dict): Data to log
        """
        try:
            with open(self.json_log_path, 'a', encoding='utf-8') as f:
                json.dump(data, f)
                f.write('\n')
        except Exception as e:
            self.system_logger.error(f"Failed to write JSON log: {e}")
    
    def log_shutdown(self, stats: Optional[dict] = None):
        """
        Log system shutdown with optional statistics.
        
        Args:
            stats (dict): Final statistics
        """
        self.system_logger.info("="*60)
        if stats:
            self.system_logger.info(f"Shutdown Statistics: {stats}")
        self.system_logger.info("DDoS Detection System Stopped")
        self.system_logger.info("="*60)
    
    def get_log_summary(self) -> dict:
        """
        Get summary of logged events.
        
        Returns:
            dict: Summary statistics
        """
        summary = {
            "event_log": os.path.join(self.log_dir, "ddos_events.log"),
            "attack_log": os.path.join(self.log_dir, "ddos_attacks.log"),
            "system_log": os.path.join(self.log_dir, "ddos_system.log"),
            "json_log": self.json_log_path,
        }
        
        # Add file sizes if they exist
        for key, path in summary.items():
            if os.path.exists(path):
                size_bytes = os.path.getsize(path)
                summary[f"{key}_size"] = f"{size_bytes / 1024:.2f} KB"
        
        return summary


# Singleton instance
_logger_instance: Optional[DDoSLogger] = None


def get_logger() -> DDoSLogger:
    """
    Get the singleton logger instance.
    
    Returns:
        DDoSLogger: Logger instance
    """
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = DDoSLogger()
    return _logger_instance


# Test the logger if run directly
if __name__ == "__main__":
    print("="*70)
    print("TESTING DDOS LOGGER MODULE")
    print("="*70)
    print()
    
    # Get logger instance
    logger = get_logger()
    
    # Test various logging functions
    print("Test 1: System event logging")
    logger.log_system_event("Testing system logger", "INFO")
    
    print("Test 2: Attack detection logging")
    logger.log_attack_detected(
        ip_address="192.168.1.100",
        attack_type="SYN_FLOOD",
        threshold=50,
        current_count=75,
        additional_info={"protocol": "TCP", "port": 80}
    )
    
    print("Test 3: IP blocking logging")
    logger.log_ip_blocked("192.168.1.100", "SYN flood attack detected", True)
    
    print("Test 4: Traffic summary logging")
    logger.log_traffic_summary({
        "total_packets": 1500,
        "unique_ips": 25,
        "blocked_ips": 1
    })
    
    print("Test 5: Error logging")
    logger.log_error("Test error message", Exception("Test exception"))
    
    print()
    print("="*70)
    print("Log Summary:")
    summary = logger.get_log_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    print()
    print("Check the 'logs/' directory for generated log files!")
    print("="*70)
