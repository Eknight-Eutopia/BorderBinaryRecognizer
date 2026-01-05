import os
import logging

from utils.logger import get_logger
from utils.utils import get_md5_hex
from config.config import config
os.environ["IDADIR"] = config["idat"]["path"]
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

logger = get_logger(__name__)


if __name__ == "__main__":
    logger.info(f"Test socket call visitor ...")
    filepath = os.path.abspath("../tmp/dhd-70b7c2327d4bb0d7/dhd")
    # filepath = os.path.abspath("../dataset/slop")
    script_path = os.path.abspath("./scripts/socket_call_visitor.py")
    logger.debug(f"file path: {filepath}")
    logger.debug(f"script path: {script_path}")
    output_path = os.path.abspath(f"../tmp/{os.path.basename(filepath)}-{get_md5_hex(filepath)}")
    opts = IdaCommandOptions(
        script_file = script_path,
        script_args = [output_path]
    )
    db = Database.open(filepath, args=opts, save_on_close=True)
    db.close()
    logger.debug(f"Test Completed!")

