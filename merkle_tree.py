import hashlib
import os
import sys
import json
from collections import deque

class MerkleTree:
    def __init__(self, file_paths, hash_function='sha1'):
        self.file_paths = file_paths
        self.hash_function = hash_function
        self.leaves = []
        self.tree = []
        self.top_hash = None

    def compute_hash(self, data):
        """Compute hash using SHA1 or MD5."""
        hash_func = hashlib.sha1() if self.hash_function == 'sha1' else hashlib.md5()
        hash_func.update(data)
        return hash_func.hexdigest()

    def compute_file_hashes(self):
        """Compute the hash for each file."""
        for file_path in self.file_paths:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    file_hash = self.compute_hash(file_data)
                    self.leaves.append(file_hash)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                sys.exit(1)

    def build_merkle_tree(self):
        """Construct the Merkle Tree and compute the Top Hash."""
        if not self.leaves:
            print("No files found to hash.")
            return

        queue = deque(self.leaves)
        while len(queue) > 1:
            new_level = deque()
            while len(queue) > 1:
                left = queue.popleft()
                right = queue.popleft()
                combined = left + right
                new_level.append(self.compute_hash(combined.encode()))
            if queue:  # If odd number of nodes, move the last one up
                new_level.append(queue.pop())
            queue = new_level

        self.top_hash = queue[0] if queue else None

    def run(self):
        self.compute_file_hashes()
        self.build_merkle_tree()
        return self.top_hash


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python merkle_tree.py <hash_method: sha1/md5> <file1> <file2> ...")
        sys.exit(1)

    hash_method = sys.argv[1]
    file_paths = sys.argv[2:]

    if hash_method not in ['sha1', 'md5']:
        print("Invalid hash method. Choose 'sha1' or 'md5'.")
        sys.exit(1)

    merkle_tree = MerkleTree(file_paths, hash_method)
    top_hash = merkle_tree.run()
    print(f"Top Hash ({hash_method}): {top_hash}")

    # Save output for submission
    with open("merkle_tree_output.json", "w") as f:
        json.dump({"Top Hash": top_hash, "Hash Method": hash_method, "Files": file_paths}, f, indent=4)

    print("Output saved to merkle_tree_output.json")
