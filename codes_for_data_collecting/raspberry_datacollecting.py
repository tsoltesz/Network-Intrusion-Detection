import sqlite3
from scapy.all import sniff, IP, TCP, UDP, Raw, sendp
from datetime import datetime

conn = sqlite3.connect('/home/pi/network_monitoring.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER,
    flags TEXT,
    message_content TEXT
)
''')
conn.commit()

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flags = None
    else:
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None

    if Raw in packet:
        message_content = str(packet[Raw].load)
    else:
        message_content = None

    cursor.execute('''
    INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, src_port,
        dst_port, length, flags, message_content)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
        length, flags, message_content))
    conn.commit()
    sendp(packet, iface="eth1", verbose=False) 

sniff(iface="eth0", prn=process_packet, store=0)
conn.close() 