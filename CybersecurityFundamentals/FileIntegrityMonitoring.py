import hashlib
import os
import json
import time
from pathlib import Path


class FileIntegrityMonitor:
    def __init__(self, baseline_file='baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.load_baseline()

    def calculate_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            print(f"Error hashing {filepath}: {e}")
            return None

    def create_baseline(self, directory):
        """Create baseline hash values for directory"""
        self.baseline = {}

        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    relative_path = os.path.relpath(filepath, directory)
                    self.baseline[relative_path] = file_hash

        self.save_baseline()
        print(f"Baseline created for {len(self.baseline)} files")

    def save_baseline(self):
        """Save baseline to file"""
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)

    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
        except FileNotFoundError:
            self.baseline = {}

    def check_integrity(self, directory):
        """Check file integrity against baseline"""
        changes = {
            'added': [],
            'removed': [],
            'modified': []
        }

        current_files = {}

        # Calculate current hashes
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    relative_path = os.path.relpath(filepath, directory)
                    current_files[relative_path] = file_hash

        # Compare with baseline
        all_files = set(self.baseline.keys()) | set(current_files.keys())

        for filepath in all_files:
            if filepath not in self.baseline:
                changes['added'].append(filepath)
            elif filepath not in current_files:
                changes['removed'].append(filepath)
            elif self.baseline[filepath] != current_files[filepath]:
                changes['modified'].append(filepath)

        return changes

    def monitor_directory(self, directory, interval=60):
        """Continuously monitor directory"""
        print(f"Monitoring {directory} every {interval} seconds...")

        while True:
            changes = self.check_integrity(directory)

            if any(changes.values()):
                print("\n=== File Integrity Alert ===")
                for change_type, files in changes.items():
                    if files:
                        print(f"{change_type.capitalize()}: {files}")

            time.sleep(interval)


# Example usage
# Create test directory and files
test_dir = "test_files"
os.makedirs(test_dir, exist_ok=True)

# Create some test files
with open(os.path.join(test_dir, "file1.txt"), "w") as f:
    f.write("Original content")

with open(os.path.join(test_dir, "file2.txt"), "w") as f:
    f.write("Another file")

# Initialize monitor
monitor = FileIntegrityMonitor()
monitor.create_baseline(test_dir)

# Check integrity
changes = monitor.check_integrity(test_dir)
print("Initial check:", changes)

# Modify a file to test detection
time.sleep(1)
with open(os.path.join(test_dir, "file1.txt"), "w") as f:
    f.write("Modified content")

# Check again
changes = monitor.check_integrity(test_dir)
print("After modification:", changes)