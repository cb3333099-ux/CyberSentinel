import socket
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from scapy.all import sniff, conf
from src.network.pcap_reader import PcapReader, PacketMetadata


class PacketCapture:
    """
    Live Network Interface Packet Capture Engine for CyberSentinel.

    Passively listens for raw packets on a selected local network interface
    and feeds PacketMetadata to a callback function.
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_requested = False
        self.interface: Optional[str] = None
        self.packets_captured: int = 0
        self.capture_errors: int = 0
        self.capture_permission: str = "UNKNOWN"  # OK, DENIED, UNKNOWN, ERROR
        self.permission_error_msg: Optional[str] = None
        self._reader = PcapReader.__new__(PcapReader)  # Uses parse_packet method

    def check_capture_permission(self, interface: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Check whether the current process has raw socket packet capture privileges.
        """
        iface = interface or self.interface or "eth0"
        try:
            # Attempt to create an AF_PACKET raw socket on Linux systems
            if hasattr(socket, "AF_PACKET") and hasattr(socket, "SOCK_RAW"):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                sock.close()
            self.capture_permission = "OK"
            self.permission_error_msg = None
            return True, "OK", "Packet capture privileges verified."
        except (PermissionError, OSError) as exc:
            msg = f"Live capture requires packet-capture privileges on interface {iface}."
            self.capture_permission = "DENIED"
            self.permission_error_msg = msg
            return False, "DENIED", msg
        except Exception as exc:
            msg = f"Error probing packet capture permissions on interface {iface}: {exc}"
            self.capture_permission = "ERROR"
            self.permission_error_msg = msg
            return False, "ERROR", msg

    @staticmethod
    def list_interfaces() -> List[Dict[str, str]]:
        """
        List available network interfaces on the local machine.
        """
        interfaces: List[Dict[str, str]] = []
        try:
            for iface in conf.ifaces.values():
                name = str(getattr(iface, "name", getattr(iface, "dev", str(iface))))
                desc = str(getattr(iface, "description", getattr(iface, "name", "Network Interface")))
                ip = str(getattr(iface, "ip", "N/A"))
                interfaces.append({
                    "name": name,
                    "description": desc,
                    "ip": ip,
                })
        except Exception:
            pass

        if not interfaces:
            # Fallback for standard interfaces
            interfaces = [
                {"name": "eth0", "description": "Ethernet Interface 0", "ip": "127.0.0.1"},
                {"name": "wlan0", "description": "Wireless Interface 0", "ip": "127.0.0.1"},
                {"name": "lo", "description": "Loopback Interface", "ip": "127.0.0.1"},
            ]

        return interfaces

    def start_capture(
        self,
        interface: str,
        packet_callback: Callable[[PacketMetadata], None],
    ) -> None:
        """
        Start passive packet capture on the specified network interface in a background thread.
        """
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Packet capture is already running.")

        is_ok, perm_status, msg = self.check_capture_permission(interface)
        if not is_ok:
            raise PermissionError(msg)

        self.interface = interface
        self._stop_requested = False
        self.packets_captured = 0
        self.capture_errors = 0

        self._thread = threading.Thread(
            target=self._sniff_worker,
            args=(interface, packet_callback),
            daemon=True,
        )
        self._thread.start()

    def _sniff_worker(
        self,
        interface: str,
        packet_callback: Callable[[PacketMetadata], None],
    ) -> None:
        """
        Background worker executing Scapy sniff loop.
        """
        def process_pkt(pkt):
            if self._stop_requested:
                return
            try:
                self.packets_captured += 1
                parsed = self._reader.parse_packet(pkt)
                if parsed is not None:
                    packet_callback(parsed)
            except Exception:
                self.capture_errors += 1

        def stop_check(pkt):
            return self._stop_requested

        try:
            sniff(
                iface=interface if interface != "auto" else None,
                prn=process_pkt,
                stop_filter=stop_check,
                store=0,
            )
            self.capture_permission = "OK"
        except (PermissionError, OSError) as exc:
            self.capture_errors += 1
            msg = f"Live capture requires packet-capture privileges on interface {interface}."
            self.capture_permission = "DENIED"
            self.permission_error_msg = msg
            print(f"[PacketCapture] Permission denied on interface '{interface}': {exc}")
        except Exception as exc:
            self.capture_errors += 1
            print(f"[PacketCapture] Sniff error on interface '{interface}': {exc}")

    def stop_capture(self) -> None:
        """
        Stop active packet capture.
        """
        self._stop_requested = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
