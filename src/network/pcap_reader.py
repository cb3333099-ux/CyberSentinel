from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, List, Optional, Union

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader as ScapyPcapReader, rdpcap


@dataclass
class PacketMetadata:
    """
    Extracted packet metadata from raw network traffic.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    pkt_len: int
    payload_len: int
    header_len: int
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    win_bytes: int = 0


class PcapReader:
    """
    PCAP / PCAPNG File Reader for CyberSentinel.

    Parses raw network packet capture files into standardized PacketMetadata
    objects without altering packet contents or fabricating network data.
    """

    def __init__(self, pcap_path: Union[str, Path]):
        self.pcap_path = Path(pcap_path)
        self.total_packets_read: int = 0
        self.skipped_packets: int = 0

    def parse_packet(self, pkt) -> Optional[PacketMetadata]:
        """
        Parse a single Scapy packet into PacketMetadata.
        Returns None if packet does not contain IP layer or supported transport.
        """
        try:
            timestamp = float(pkt.time)

            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                proto = int(ip_layer.proto)
                ip_hdr_len = int(ip_layer.ihl) * 4 if hasattr(ip_layer, "ihl") else 20
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                proto = int(ip_layer.nh)
                ip_hdr_len = 40
            else:
                return None

            src_port = 0
            dst_port = 0
            transport_hdr_len = 0
            payload_len = 0
            win_bytes = 0
            tcp_flags = {
                "FIN": False, "SYN": False, "RST": False,
                "PSH": False, "ACK": False, "URG": False,
                "ECE": False, "CWE": False,
            }

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                transport_hdr_len = int(tcp_layer.dataofs) * 4 if hasattr(tcp_layer, "dataofs") else 20
                win_bytes = int(tcp_layer.window) if hasattr(tcp_layer, "window") else 0
                payload_len = len(tcp_layer.payload) if hasattr(tcp_layer, "payload") else 0

                # Parse TCP flags
                flags_val = int(tcp_layer.flags) if hasattr(tcp_layer, "flags") else 0
                tcp_flags = {
                    "FIN": bool(flags_val & 0x01),
                    "SYN": bool(flags_val & 0x02),
                    "RST": bool(flags_val & 0x04),
                    "PSH": bool(flags_val & 0x08),
                    "ACK": bool(flags_val & 0x10),
                    "URG": bool(flags_val & 0x20),
                    "ECE": bool(flags_val & 0x40),
                    "CWE": bool(flags_val & 0x80),
                }

            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                transport_hdr_len = 8
                payload_len = len(udp_layer.payload) if hasattr(udp_layer, "payload") else 0

            elif pkt.haslayer(ICMP):
                transport_hdr_len = 8
                payload_len = len(pkt[ICMP].payload) if hasattr(pkt[ICMP], "payload") else 0

            else:
                # Other IP protocol
                transport_hdr_len = 0
                payload_len = len(ip_layer.payload) if hasattr(ip_layer, "payload") else 0

            pkt_len = len(pkt)
            header_len = ip_hdr_len + transport_hdr_len

            return PacketMetadata(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                pkt_len=pkt_len,
                payload_len=payload_len,
                header_len=header_len,
                tcp_flags=tcp_flags,
                win_bytes=win_bytes,
            )

        except Exception:
            return None

    def read_packets(self) -> Generator[PacketMetadata, None, None]:
        """
        Yield PacketMetadata objects from the PCAP file sequentially.
        """
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        self.total_packets_read = 0
        self.skipped_packets = 0

        try:
            with ScapyPcapReader(str(self.pcap_path)) as pcap_reader:
                for pkt in pcap_reader:
                    self.total_packets_read += 1
                    parsed = self.parse_packet(pkt)
                    if parsed is not None:
                        yield parsed
                    else:
                        self.skipped_packets += 1
        except Exception:
            # Fallback to rdpcap if stream reader fails
            packets = rdpcap(str(self.pcap_path))
            for pkt in packets:
                self.total_packets_read += 1
                parsed = self.parse_packet(pkt)
                if parsed is not None:
                    yield parsed
                else:
                    self.skipped_packets += 1
