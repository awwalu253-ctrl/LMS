import os
import sys
import time

print("Force resetting database...")

# Files to delete
files_to_delete = [
    'lms_database.db',
    'lms_database.db-journal',
    'lms_database.db-wal',
    'lms_database.db-shm',
    'lms.log'
]

for file in files_to_delete:
    if os.path.exists(file):
        try:
            os.remove(file)
            print(f"✓ Deleted: {file}")
            time.sleep(0.1)
        except Exception as e:
            print(f"✗ Could not delete {file}: {e}")

print("\nAll lock files cleared. Database will be recreated when server starts.")