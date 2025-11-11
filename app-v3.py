# To do
# 1. Make a pathfinder function
# 2. Compare yara
# 3. Add option to delete file if a marker was found

import pyshark
import os


def analyze_pcap(pcap_file):
    print(f"[*] Analyzing {pcap_file} ...")

    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    total_packets = 0
    smb_packets = 0
    file_names = []

    # allowed file extensions
    allowed_extensions = ('.exe', '.txt', '.pdf', '.doc', '.docx', '.xls',
                          '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.png', '.jpg', '.jpeg', '.csv')

    for packet in capture:
        total_packets += 1

        if 'smb' in packet or 'smb2' in packet:
            smb_packets += 1

            try:
                file_name = None

                if 'smb' in packet and hasattr(packet.smb, 'filename'):
                    file_name = str(packet.smb.filename)
                elif 'smb2' in packet and hasattr(packet.smb2, 'filename'):
                    file_name = str(packet.smb2.filename)

                if file_name:
                    # remove trailing dots or spaces
                    file_name = file_name.strip().replace('\x00', '')

                    # if it ends with allowed extensions
                    if file_name.lower().endswith(allowed_extensions):
                        if file_name not in file_names:
                            file_names.append(file_name)

            except AttributeError:
                pass

    capture.close()

    print("\n=== SMB Packet Analysis ===")
    print(f"Total packets: {total_packets}")
    print(f"SMB packets: {smb_packets}")
    print(f"Valid filenames found: {len(file_names)}")

    if file_names:
        print("\nFiles transferred or accessed:")
        for fname in file_names:
            print(f" - {fname}")
    else:
        print("\nNo valid filenames found in SMB traffic.")

    return file_names


if __name__ == "__main__":
    pcap_path = input(
        "Enter the path or filename of the .pcap/.pcapng file: ").strip()

    if not pcap_path or not os.path.exists(pcap_path):
        print("Error: File not found.")
    else:
        files = analyze_pcap(pcap_path)
        print("\n[*] file_names array:")
        print(files)
