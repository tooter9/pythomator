__version__ = "2.0"
__author__  = "pythomator contributors"
__license__ = "GPL-3.0"

from .vault  import Vault, create_vault
from .crypto import encrypt_file_content, decrypt_file_content

__all__ = [
    "Vault",
    "create_vault",
    "encrypt_file_content",
    "decrypt_file_content",
    "__version__",
]
