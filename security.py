import hashlib

import machineid

SALT = "BHYG_" + "OS" + "S_SALT"
MACHINE_ID = hashlib.sha256(machineid.hashed_id().encode() + SALT.encode()).hexdigest()
HASHED_MACHINE_ID = hashlib.sha256(MACHINE_ID.encode()).hexdigest()[:7]


def get_machine_id() -> str:
    return HASHED_MACHINE_ID