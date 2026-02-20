import hashlib

def generate_file_hash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

file = "files/sample.txt"
print(f"SHA256 Hash of {file}:\n{generate_file_hash(file)}")
