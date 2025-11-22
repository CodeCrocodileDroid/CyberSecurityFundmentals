import re
from datetime import datetime
from collections import Counter, defaultdict


class LogAnalyzer:
    def __init__(self):
        # Common attack patterns
        self.attack_patterns = {
            'sql_injection': r"(UNION|SELECT|INSERT|UPDATE|DELETE).*['\";]",
            'xss': r"(<script|javascript:|onload=|onerror=)",
            'directory_traversal': r"(\.\./|\.\.\\)",
            'command_injection': r"(&&|\|\||;|\$\(.*\))",
        }

        self.suspicious_ips = Counter()
        self.attack_types = Counter()

    def parse_apache_log(self, log_line):
        """Parse Apache log format"""
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \S+ "([^"]*)" "([^"]*)"'
        match = re.match(pattern, log_line)

        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'status': int(match.group(5)),
                'user_agent': match.group(7)
            }
        return None

    def detect_attacks(self, log_entry):
        """Detect potential attacks in log entry"""
        if not log_entry:
            return []

        attacks = []
        url = log_entry.get('url', '')

        for attack_type, pattern in self.attack_patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                attacks.append(attack_type)
                self.suspicious_ips[log_entry['ip']] += 1
                self.attack_types[attack_type] += 1

        # Detect brute force (multiple failed logins)
        if log_entry.get('status') == 401:
            self.suspicious_ips[log_entry['ip']] += 1

        return attacks

    def analyze_log_file(self, filename):
        """Analyze entire log file"""
        with open(filename, 'r') as f:
            for line in f:
                log_entry = self.parse_apache_log(line.strip())
                attacks = self.detect_attacks(log_entry)

                if attacks:
                    print(f"Suspicious activity from {log_entry['ip']}: {', '.join(attacks)}")

    def generate_report(self):
        """Generate security report"""
        print("\n=== Security Analysis Report ===")
        print(f"Total suspicious IPs: {len(self.suspicious_ips)}")
        print("\nTop suspicious IPs:")
        for ip, count in self.suspicious_ips.most_common(5):
            print(f"  {ip}: {count} suspicious activities")

        print("\nAttack types detected:")
        for attack_type, count in self.attack_types.items():
            print(f"  {attack_type}: {count} occurrences")


# Example log dataset
sample_logs = [
    '192.168.1.100 - - [25/Dec/2023:10:00:00 +0000] "GET /index.php?id=1\' UNION SELECT * FROM users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.50 - - [25/Dec/2023:10:01:00 +0000] "GET /admin.php?file=../../../../etc/passwd HTTP/1.1" 404 567 "-" "curl/7.68.0"',
    '172.16.0.25 - - [25/Dec/2023:10:02:00 +0000] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0"'
]

# Create sample log file
with open('sample_access.log', 'w') as f:
    for log in sample_logs:
        f.write(log + '\n')

# Analyze logs
analyzer = LogAnalyzer()
analyzer.analyze_log_file('sample_access.log')
analyzer.generate_report()