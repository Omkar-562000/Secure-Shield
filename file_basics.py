# file_basics.py

# Write to file
with open("files/sample.txt", "w") as f:
    f.write("This is a test file for SecureShield.\n")

# Append more data
with open("files/sample.txt", "a") as f:
    f.write("Adding more data...\n")

# Read file content
with open("files/sample.txt", "r") as f:
    content = f.read()
    print("File Content:\n", content)
