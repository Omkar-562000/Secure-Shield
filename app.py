from flask import Flask, render_template_string
import hashlib

app = Flask(__name__)

def generate_file_hash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route('/')
def home():
    file = "files/sample.txt"
    hash_value = generate_file_hash(file)
    html = f"""
    <h2>SecureShield</h2>
    <p>File: {file}</p>
    <p>SHA256: {hash_value}</p>
    """
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True)
