import json
import machineid
import hashlib
import secrets
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

from Crypto.Util.Padding import pad, unpad
import base64
from loguru import logger
import httpx

logger.remove()
logger.add(
    sys.stdout,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <cyan> SECURITY </cyan> | <level>{level: <8}</level> | <level>{message}</level>",
)

ENDPOINT = "https://not.available.in.oss.invalid/api/client/v2"
RSA_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJFB2p2F14VcOyhg4GyytvcfeB
QGct5svBBZa48nwuyknr3ZLzxNwYwB2IxTTedB4EqZJD+7KRpTjRvuQ77t9u82zF
bKl9V34naUl7Kap1uSuvxoe9XOAvyTNTyPPiSxE6HtbFn4/uA/nKGzox+zVQlq1b
S/pPof5iaElGRUW98QIDAQAB
-----END PUBLIC KEY-----"""

SALT = "BHYG_OSS_SALT"
MACHINE_ID = hashlib.sha256(machineid.hashed_id().encode()+SALT.encode()).hexdigest()
HASHED_MACHINE_ID = hashlib.sha256(MACHINE_ID.encode()).hexdigest()[:7]

FALLBACK_POLICY = {
    "allow_run": False
}

FAILED_TIME = 0

POLICY = FALLBACK_POLICY

def get_machine_id() -> str:
    return HASHED_MACHINE_ID

def get_policy_value(key: str, default=None):
    # NOT AVAILABLE IN OSS
    raise Exception("NOT AVAILABLE IN OSS")

def fetch_policy(version: str) -> dict:
    # NOT AVAILABLE IN OSS
    raise Exception("NOT AVAILABLE IN OSS")
    
def heartbeat(version: str, uid: str):
    # NOT AVAILABLE IN OSS
    raise Exception("NOT AVAILABLE IN OSS")

def check_signature() -> str:
    try:
        with open(sys.argv[0], "rb") as f:
            executable_data = f.read()
        data = executable_data[-256:-128]
        data = data.rstrip(b'\x00')
        print(f"Data to verify: {data}")
        data_signature = executable_data[-128:]
        print(f"Data signature: {data_signature}")
        rsa_key = RSA.import_key(RSA_PUBKEY)
        pkcs1_15.new(rsa_key).verify(SHA1.new(data), data_signature)
        return data.decode()
    except (ValueError, TypeError):
        print("Warning: Signature verification failed!")
        return None