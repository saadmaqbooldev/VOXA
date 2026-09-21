import logging
from logging.handlers import RotatingFileHandler

from voxa.config import settings

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            settings.log_dir / "voxa.log", maxBytes=5_000_000, backupCount=5
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.basicConfig(level=settings.log_level, handlers=[handler])
        _CONFIGURED = True
    return logging.getLogger(name)
