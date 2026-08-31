# This file contains Cryptographic constants and Shared Configs

import hashlib

#Network constans

SERVER_HOST = "127.0.0.1" #Loopback IP
SPA_PORT = 9999 #Secret Dormant Port
SOCKET_TIMEOUT = 2.0

#Hashing params for security
_PASSPHRASE = b"CP-SPA-ZeroTouchNetwork-ResearchTestbed-2026"
PRE_SHARED_KEY = hashlib.sha256(_PASSPHRASE).digest() #SHA-256 Hashing

#Anti recording params
MAX_PAYLOAD_AGE = 5 #seconds
NONCE_SIZE = 12 #bytes

OPEN_DURATION = 8 #seconds