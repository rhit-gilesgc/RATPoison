import subprocess
from scapy.all import sniff
from scapy.layers.inet import TCP
import struct

john_exe_path = "C:\\Users\\gilesgc\\Classes\\CSSE490\\john-the-ripper\\run"

def crack_hash(hash_str):
    with open("hash.txt", "w") as file:
        file.write("RAT PASSWORD:" + hash_str)

    args = ["--wordlist=wiki-100k.txt", "--format=raw-sha256", "hash.txt"]

    try:
        subprocess.run(["del", "john.pot"], cwd=john_exe_path, shell=True)
    except:
        pass

    subprocess.run([john_exe_path + "\\john.exe"] + args)

def process_packet(packet):

    if packet.haslayer(TCP) and len(packet[TCP].payload) == 2048:
        packet_id, hash_bytes = struct.unpack("I 32s", packet[TCP].payload.load[:36])

        if packet_id == 0:
            hash_str = hash_bytes.hex()
            print(f"Intercepted password hash {hash_str}")
            print("Cracking...")
            crack_hash(hash_str)

print("Sniffing for RAT password packets...")
sniff(iface="\\Device\\NPF_Loopback", prn=process_packet)
