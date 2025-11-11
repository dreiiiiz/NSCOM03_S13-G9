import pyshark


def analyze_pcap(pcap_file):
    print(f"[*] Analyzing {pcap_file} ...")

    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    total_packets = 0
    smb_packets = 0
    file_names = []  # list to store filenames

    for packet in capture:
        total_packets += 1

        # Detect SMB or SMB2 packets
        if 'smb' in packet or 'smb2' in packet:
            smb_packets += 1

            try:
                # SMB (v1)
                if 'smb' in packet:
                    if hasattr(packet.smb, 'filename'):
                        file_name = str(packet.smb.filename)
                        if file_name not in file_names:
                            file_names.append(file_name)

                # SMB2 (v2/v3)
                elif 'smb2' in packet:
                    if hasattr(packet.smb2, 'filename'):
                        file_name = str(packet.smb2.filename)
                        if file_name not in file_names:
                            file_names.append(file_name)

            except AttributeError:
                pass  # Some SMB packets don't have filename fields

    capture.close()

    print("\n=== SMB Packet Analysis ===")
    print(f"Total packets: {total_packets}")
    print(f"SMB packets: {smb_packets}")
    print(f"Filenames found: {len(file_names)}")

    if file_names:
        print("\nFiles transferred or accessed:")
        for fname in file_names:
            print(f" - {fname}")
    else:
        print("\nNo filenames found in SMB traffic.")

    return file_names


if __name__ == "__main__":
    # Ask user for file path interactively
    pcap_path = input(
        "Enter the path or filename of the .pcap/.pcapng file: ").strip()

    if not pcap_path:
        print("Error: No file specified.")
    else:
        files = analyze_pcap(pcap_path)
        print("\n[*] file_names array:")
        print(files)
