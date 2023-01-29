import yara

def detect_yara_rules(file_path):
    # Compile the rules from a file
    rules = yara.compile('/home/srihari/Documents/projects/malspark/yara/packers.yara')
    # Scan the file
    matches = rules.match(file_path)
    # Print the matched rule names
    for match in matches:
        if match.rule:
            print(match.rule)
            break

# Detect Yara rules in a file
detect_yara_rules('/home/srihari/Documents/projects/malspark/samples/upx_ADExplorer.exe')
