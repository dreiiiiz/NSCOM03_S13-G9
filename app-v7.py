""""
    NSCOM03_S13_G9

    Members:
        De Jesus, Andrei Zarmin D.
        Jacela, Eugo P.
        Sayat, John Christian N.
"""


import pyshark
import os
import yara


def analyze_pcap(pcap_file):
    # Print which pcap file is being analyzed
    print(f"[*] Analyzing {pcap_file} ...")

    # Load the PCAP file using pyshark (no packet retention to save memory)
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    total_packets = 0       # Count all packets
    smb_packets = 0         # Count SMB/SMB2 packets
    file_names = []         # Store extracted filenames

    # Allowed file extensions
    allowed_extensions = ('.exe', '.txt', '.pdf', '.doc', '.docx', '.xls',
                          '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.png', '.jpg', '.jpeg', '.csv')

    # Loop through every packet in the capture
    for packet in capture:
        total_packets += 1      # Increase total packet count

        if 'smb' in packet or 'smb2' in packet:
            smb_packets += 1    # Increase SMB-related packet count

            try:
                file_name = None

                # Extract filename for SMBv1
                if 'smb' in packet and hasattr(packet.smb, 'filename'):
                    file_name = str(packet.smb.filename)

                # Extract filename for SMBv2
                elif 'smb2' in packet and hasattr(packet.smb2, 'filename'):
                    file_name = str(packet.smb2.filename)

                # Clean and save filename if valid
                if file_name:
                    file_name = file_name.strip().replace('\x00', '')

                    # Check if filename ends with allowed extensions
                    if file_name.lower().endswith(allowed_extensions):

                        # Avoid duplicates
                        if file_name not in file_names:
                            file_names.append(file_name)

            except AttributeError:
                pass

    # Close PCAP so pyshark releases resources
    capture.close()

    # Print summary of analysis
    print("\n=== SMB Packet Analysis ===")
    print(f"Total packets: {total_packets}")
    print(f"SMB packets: {smb_packets}")
    print(f"Valid filenames found: {len(file_names)}")

    # Display extracted filenames
    if file_names:
        print("\nFiles transferred or accessed:")
        for fname in file_names:
            print(f" - {fname}")
    else:
        print("\nNo valid filenames found in SMB traffic.")

    return file_names


def find_file_system_path(filename, search_dir=None):
    # Default search directory: full file system (C:\ on Windows)
    if search_dir is None:
        search_dir = 'C:\\' if os.name == 'nt' else '/'

    matches = []  # Store all matching paths

    # Walk through all folders and files inside search_dir
    for root, dirs, files in os.walk(search_dir):
        # Check if filename exists in current directory
        if filename in files:
            matches.append(os.path.join(root, filename))

    # Return all found file paths
    return matches


def scan_with_yara(file_path, rule_path="rules_collection"):
    try:
        matched_rules = []  # Store names of rules that matched

        # If rule_path is a directory, scan all .yar files inside it
        if os.path.isdir(rule_path):
            yara_files = [f for f in os.listdir(
                rule_path) if f.endswith(".yar")]
            for yara_file in yara_files:
                full_path = os.path.join(rule_path, yara_file)
                try:
                    # Compile individual rule file
                    rules = yara.compile(filepath=full_path)

                    # Run YARA scan on the file
                    matches = rules.match(file_path)

                    # Normalize output (match objects or strings)
                    for m in matches:
                        rule_name = m.rule if hasattr(m, "rule") else str(m)
                        matched_rules.append(f"{yara_file}: {rule_name}")
                except Exception as e:
                    # Continue even if one rule file has errors
                    print(f"[!] Error in {yara_file}: {e}")

        else:
            # If rule_path is a single file, compile and scan normally
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(file_path)

            # Normalize output for single rule file
            for m in matches:
                rule_name = m.rule if hasattr(m, "rule") else str(m)
                matched_rules.append(rule_name)

        # Return all matched rule names
        return matched_rules

    except Exception as e:
        # Catch any general error during YARA scan
        print(f"[!] Error scanning {file_path} with YARA: {e}")
        return []


if __name__ == "__main__":
    # Ask user for PCAP file path
    pcap_path = input(
        "Enter the path or filename of the .pcap/.pcapng file: ").strip()

    # Check if file exists
    if not pcap_path or not os.path.exists(pcap_path):
        print("Error: File not found.")
    else:
        # Analyze PCAP and extract filenames
        files = analyze_pcap(pcap_path)

        # Ask user if they want to search the local system for these files
        choice = input(
            "\nSearch for these files on the system? (y/n): ").strip().lower()

        if choice == 'y':
            # Ask user for directory to search (or full system)
            search_dir = input(
                "Enter directory to search (leave empty for full system): ").strip() or None

            # Search each extracted filename
            for fname in files:
                paths = find_file_system_path(fname, search_dir)
                if paths:
                    print(f"\nFound '{fname}' in {len(paths)} location(s):")
                    for p in paths:
                        print(f" - {p}")

                        # Run YARA scan on each found file
                        yara_matches = scan_with_yara(p)

                        # Display results
                        if yara_matches:
                            print(
                                f"   ⚠️  YARA MATCH: {', '.join(yara_matches)} — Suspicious/Malicious!")
                        else:
                            print(f"   ✅  No YARA match — File appears safe.")
                else:
                    print(f"\n'{fname}' not found on the system.")
