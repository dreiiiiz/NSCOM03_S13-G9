import pyshark
import os
import yara

# for faster scanning C:\Users or C:\Users\dj_za\Desktop


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
                    file_name = file_name.strip().replace('\x00', '')
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


def find_file_system_path(filename, search_dir=None):
    if search_dir is None:
        search_dir = 'C:\\' if os.name == 'nt' else '/'

    matches = []

    for root, dirs, files in os.walk(search_dir):
        if filename in files:
            matches.append(os.path.join(root, filename))

    return matches


def scan_with_yara(file_path, rule_path="rules_collection"):
    try:
        matched_rules = []

        # If rule_path is a folder, iterate over all .yar files inside
        if os.path.isdir(rule_path):
            yara_files = [f for f in os.listdir(
                rule_path) if f.endswith(".yar")]
            for yara_file in yara_files:
                full_path = os.path.join(rule_path, yara_file)
                try:
                    rules = yara.compile(filepath=full_path)
                    matches = rules.match(file_path)

                    # Normalize output (match objects or strings)
                    for m in matches:
                        rule_name = m.rule if hasattr(m, "rule") else str(m)
                        matched_rules.append(f"{yara_file}: {rule_name}")
                except Exception as e:
                    print(f"[!] Error in {yara_file}: {e}")

        else:
            # Single .yar file path (backward compatibility)
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(file_path)
            for m in matches:
                rule_name = m.rule if hasattr(m, "rule") else str(m)
                matched_rules.append(rule_name)

        return matched_rules

    except Exception as e:
        print(f"[!] Error scanning {file_path} with YARA: {e}")
        return []


if __name__ == "__main__":
    pcap_path = input(
        "Enter the path or filename of the .pcap/.pcapng file: ").strip()

    if not pcap_path or not os.path.exists(pcap_path):
        print("Error: File not found.")
    else:
        files = analyze_pcap(pcap_path)

        # Ask user if they want to search the system for these files
        choice = input(
            "\nSearch for these files on the system? (y/n): ").strip().lower()
        if choice == 'y':
            search_dir = input(
                "Enter directory to search (leave empty for full system): ").strip() or None

            for fname in files:
                paths = find_file_system_path(fname, search_dir)
                if paths:
                    print(f"\nFound '{fname}' in {len(paths)} location(s):")
                    for p in paths:
                        print(f" - {p}")

                        # Run YARA scan
                        yara_matches = scan_with_yara(p)
                        if yara_matches:
                            print(
                                f"   ⚠️  YARA MATCH: {', '.join(yara_matches)} — Suspicious/Malicious!")
                        else:
                            print(f"   ✅  No YARA match — File appears safe.")
                else:
                    print(f"\n'{fname}' not found on the system.")
