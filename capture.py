import argparse
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

try:
    from scapy.all import sniff, IP, UDP, TCP, Raw
    from scapy.config import conf
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
except ImportError as e:
    print(f"Error importing required packages: {e}")
    print("Please install dependencies with: pip install scapy rich")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("protocol_capture.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    DEFAULT_TOOL = "curl"
    SUPPORTED_TOOLS = ["curl", "gocurl"]
    DEFAULT_TIMEOUT = 10
    MAX_RETRIES = 5
    QUIC_PACKET_LENGTHS = {"curl": 1200, "gocurl": 1252}
    OUTPUT_DIR = "captures"

    @classmethod
    def ensure_output_dir(cls) -> None:
        os.makedirs(cls.OUTPUT_DIR, exist_ok=True)

class ProtocolCaptureError(Exception):
    pass

class DomainResolutionError(ProtocolCaptureError):
    pass

class PacketCaptureError(ProtocolCaptureError):
    pass

class ToolExecutionError(ProtocolCaptureError):
    pass

class ProtocolAnalyzer:
    
    def __init__(self, domain: str, tool: str = Config.DEFAULT_TOOL, output_dir: str = Config.OUTPUT_DIR):
        self.domain = domain
        self.tool = tool if tool in Config.SUPPORTED_TOOLS else Config.DEFAULT_TOOL
        self.output_dir = output_dir
        self.console = Console()
        self._validate_tool()
        
        self.tls_result: Optional[bytes] = None
        self.quic_result: Optional[bytes] = None
        
    def _validate_tool(self) -> None:
        if self.tool == "curl":
            if not shutil.which("curl"):
                raise ToolExecutionError("curl not found in PATH")
        elif self.tool == "gocurl":
            if not shutil.which("gocurl"):
                raise ToolExecutionError("gocurl not found in PATH")
    
    def resolve_domain(self) -> str:
        try:
            return socket.gethostbyname(self.domain)
        except socket.gaierror as e:
            raise DomainResolutionError(f"Failed to resolve {self.domain}: {e}")
    
    def capture_tls(self) -> None:
        port = random.randint(2000, 65000)
        ip_address = self.resolve_domain()
        output_file = Path(self.output_dir) / f"tls_clienthello_{self.domain.replace('.', '_')}.bin"
        
        proxy_thread = threading.Thread(
            target=self._run_tcp_proxy,
            args=(port, ip_address, output_file),
            daemon=True
        )
        proxy_thread.start()
        
        time.sleep(0.5)
        
        curl_cmd = [
            self.tool,
            "--tlsv1.3",
            "-k",
            "--connect-to", f"{self.domain}:443:127.0.0.1:{port}",
            "-IS", f"https://{self.domain}"
        ]
        
        try:
            subprocess.run(
                curl_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=Config.DEFAULT_TIMEOUT
            )
        except subprocess.TimeoutExpired:
            logger.warning("Curl command timed out")
        except Exception as e:
            logger.error(f"Error running curl command: {e}")
        
        proxy_thread.join(timeout=5)
        
        if output_file.exists() and output_file.stat().st_size > 0:
            self.tls_result = output_file.read_bytes()
            self._display_result("TLS ClientHello", self.tls_result, output_file)
        else:
            raise PacketCaptureError("Failed to capture TLS ClientHello")
    
    def _run_tcp_proxy(self, listen_port: int, target_ip: str, output_file: Path) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', listen_port))
                s.listen(1)
                
                conn, _ = s.accept()
                with conn:
                    data = conn.recv(4096)
                    if data:
                        output_file.write_bytes(data)
        except Exception as e:
            logger.error(f"Error in TCP proxy: {e}")
    
    def capture_quic(self) -> None:
        port = random.randint(2000, 65000)
        ip_address = self.resolve_domain()
        output_file = Path(self.output_dir) / f"quic_initial_{self.domain.replace('.', '_')}.bin"
        expected_length = Config.QUIC_PACKET_LENGTHS.get(self.tool, 1200)
        
        stop_event = threading.Event()
        udp_thread = threading.Thread(
            target=self._run_udp_listener,
            args=(port, ip_address, output_file, expected_length, stop_event),
            daemon=True
        )
        udp_thread.start()
        
        time.sleep(0.5)
        
        curl_cmd = [
            self.tool,
            "-k",
            "--connect-to", f"{self.domain}:443:127.0.0.1:{port}",
            "--http3-only" if self.tool == "curl" else "--http3",
            "-IS", f"https://{self.domain}"
        ]
        
        for attempt in range(1, Config.MAX_RETRIES + 1):
            logger.info(f"QUIC capture attempt {attempt}/{Config.MAX_RETRIES}")
            
            try:
                subprocess.run(
                    curl_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=Config.DEFAULT_TIMEOUT
                )
            except subprocess.TimeoutExpired:
                logger.warning("Curl command timed out")
            except Exception as e:
                logger.error(f"Error running curl command: {e}")
            
            if output_file.exists() and output_file.stat().st_size >= expected_length:
                break
            
            time.sleep(1)
        
        stop_event.set()
        udp_thread.join(timeout=5)
        
        if output_file.exists() and output_file.stat().st_size >= expected_length:
            self.quic_result = output_file.read_bytes()
            self._display_result("QUIC Initial", self.quic_result, output_file)
        else:
            raise PacketCaptureError(f"Failed to capture QUIC Initial packet of size {expected_length} bytes")
    
    def _run_udp_listener(self, listen_port: int, target_ip: str, output_file: Path, 
                         expected_length: int, stop_event: threading.Event) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', listen_port))
                
                s.settimeout(1)
                
                while not stop_event.is_set():
                    try:
                        data, _ = s.recvfrom(65535)
                        if len(data) >= expected_length:
                            output_file.write_bytes(data)
                            break
                    except socket.timeout:
                        continue
        except Exception as e:
            logger.error(f"Error in UDP listener: {e}")
    
    def _display_result(self, protocol: str, data: bytes, output_file: Path) -> None:
        table = Table(title=f"{protocol} Capture Results", show_header=True, header_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        
        table.add_row("Domain", self.domain)
        table.add_row("Protocol", protocol)
        table.add_row("Output File", str(output_file))
        table.add_row("File Size", f"{len(data)} bytes")
        table.add_row("Capture Time", datetime.now().isoformat())
        
        hex_dump = ' '.join(f"{b:02x}" for b in data[:32])
        table.add_row("First 32 Bytes", hex_dump)
        
        self.console.print(table)
    
    def verify_packets(self) -> bool:
        results = []
        
        if self.tls_result:
            is_valid = len(self.tls_result) > 5 and self.tls_result[0] == 0x16 and self.tls_result[5] == 0x01
            status = "✅ Valid" if is_valid else "❌ Invalid"
            results.append(("TLS ClientHello", status))
        
        if self.quic_result:
            is_valid = len(self.quic_result) > 0 and (self.quic_result[0] & 0xF0) == 0xC0
            status = "✅ Valid" if is_valid else "❌ Invalid"
            results.append(("QUIC Initial", status))
        
        if results:
            table = Table(title="Packet Verification", show_header=True, header_style="bold blue")
            table.add_column("Packet Type", style="cyan")
            table.add_column("Status")
            
            for packet_type, status in results:
                table.add_row(packet_type, status)
            
            self.console.print(table)
            return all("✅" in status for _, status in results)
        
        return False

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Network Protocol Capture and Analysis Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--tls", action="store_true", help="Capture only TLS ClientHello")
    group.add_argument("-q", "--quic", action="store_true", help="Capture only QUIC Initial")
    group.add_argument("-a", "--all", action="store_true", help="Capture both TLS and QUIC")
    
    parser.add_argument("--tool", choices=Config.SUPPORTED_TOOLS, default=Config.DEFAULT_TOOL,
                       help="HTTP client tool to use")
    parser.add_argument("--output", default=Config.OUTPUT_DIR,
                       help="Output directory for capture files")
    parser.add_argument("--test", action="store_true",
                       help="Test mode (verify dependencies and permissions)")
    parser.add_argument("domain", nargs="?", help="Target domain name")
    
    args = parser.parse_args()
    
    if not any([args.tls, args.quic, args.all]):
        args.tls = True
    
    return args

def check_dependencies() -> bool:
    requirements = [
        ("scapy", lambda: hasattr(conf, "version")),
        ("rich", lambda: "Console" in globals()),
        ("curl", lambda: shutil.which("curl") is not None),
    ]
    
    table = Table(title="Dependency Check", show_header=True, header_style="bold green")
    table.add_column("Package", style="cyan")
    table.add_column("Status")
    
    all_ok = True
    
    for name, check in requirements:
        try:
            if check():
                status = "[green]✓ Installed[/green]"
            else:
                status = "[red]✗ Missing[/red]"
                all_ok = False
        except Exception:
            status = "[red]✗ Error checking[/red]"
            all_ok = False
        
        table.add_row(name, status)
    
    console = Console()
    console.print(table)
    
    return all_ok

def main() -> None:
    args = parse_args()
    
    if args.test:
        logger.info("Running in test mode")
        if check_dependencies():
            logger.info("All dependencies are satisfied")
            sys.exit(0)
        else:
            logger.error("Missing required dependencies")
            sys.exit(1)
    
    if not args.domain:
        logger.error("Target domain is required")
        sys.exit(1)
    
    try:
        Config.ensure_output_dir()
        analyzer = ProtocolAnalyzer(args.domain, args.tool, args.output)
        
        with ThreadPoolExecutor() as executor:
            futures = []
            
            if args.tls or args.all:
                futures.append(executor.submit(analyzer.capture_tls))
            
            if args.quic or args.all:
                futures.append(executor.submit(analyzer.capture_quic))
            
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Capture failed: {e}")
        
        analyzer.verify_packets()
        
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
