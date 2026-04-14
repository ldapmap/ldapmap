import logging
import sys
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

SUCCESS_LEVEL = 25
VULN_LEVEL = 60
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.addLevelName(VULN_LEVEL, "VULN")


class LDAPMapFormatter(logging.Formatter):
    GRAY = Fore.LIGHTBLACK_EX
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

    def format(self, record):
        ct = datetime.now().strftime("%H:%M:%S")
        ts = self.GRAY + "[" + ct + "]" + self.RESET

        if record.levelno == VULN_LEVEL:
            ls = self.GRAY + "(" + self.RED + "VULN" + self.GRAY + ")" + self.RESET
        elif record.levelno == SUCCESS_LEVEL:
            ls = self.GRAY + "(" + self.GREEN + "OK" + self.GRAY + ")" + self.RESET
        elif record.levelno == logging.INFO:
            ls = self.GRAY + "(" + self.CYAN + "INFO" + self.GRAY + ")" + self.RESET
        elif record.levelno == logging.WARNING:
            ls = self.GRAY + "(" + self.YELLOW + "WARN" + self.GRAY + ")" + self.RESET
        elif record.levelno == logging.ERROR:
            ls = self.GRAY + "(" + self.RED + "ERR" + self.GRAY + ")" + self.RESET
        elif record.levelno == logging.DEBUG:
            ls = self.GRAY + "(" + self.WHITE + "DBG" + self.GRAY + ")" + self.RESET
        else:
            ls = self.GRAY + "(LOG)" + self.RESET

        msg = self.WHITE + record.getMessage() + self.RESET
        return ts + " " + ls + " " + msg


class LDAPMapLogger(logging.Logger):
    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(SUCCESS_LEVEL):
            self._log(SUCCESS_LEVEL, msg, args, **kwargs)

    def vuln(self, msg, *args, **kwargs):
        if self.isEnabledFor(VULN_LEVEL):
            self._log(VULN_LEVEL, msg, args, **kwargs)


def setup_logger(name="ldapmap", level=logging.INFO):
    logging.setLoggerClass(LDAPMapLogger)
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(LDAPMapFormatter())
    logger.addHandler(console_handler)

    return logger
