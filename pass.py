import base64
import hashlib
import hmac
import secrets
import getpass

PBKDF2_ITERATIONS = 310000


def _pbkdf2_hash(password: str, salt: bytes, iterations: int) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return base64.b64encode(dk).decode("ascii")


def make_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest = _pbkdf2_hash(password, salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        alg, iterations, salt_b64, digest = stored_hash.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"))
        candidate = _pbkdf2_hash(password, salt, int(iterations))
        return hmac.compare_digest(candidate, digest)
    except (ValueError, OSError):
        return False


WEB_USER = "admin"
# Default hash matches password "admin123"
WEB_PASS_HASH = "pbkdf2_sha256$310000$TPrPH1j7KLCTzoCohfBzeA==$V7xz0dc6nENgcgBOPApFfKJpUDp7m5VqyNiBelOuB/E="
FTP_PASS = "hardcore"


if __name__ == "__main__":
    pwd = getpass.getpass("New password: ")
    print(make_password_hash(pwd))
