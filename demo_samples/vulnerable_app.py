import hashlib
import os
import pickle
import sqlite3
import subprocess

password = "super_secret_password"
api_token = "tok_1234567890abcdef"
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"


def run_untrusted(user_code, user_input):
    eval(user_code)
    exec("print('executed')")
    os.system("echo " + user_input)
    subprocess.run(f"ls {user_input}", shell=True)


def parse_payload(blob):
    return pickle.loads(blob)


def weak_hashing(data):
    digest = hashlib.md5(data).hexdigest()
    return digest


def risky_sql(username):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cur.execute(query)


try:
    run_untrusted("print('hello')", "*.py")
except Exception:
    pass
