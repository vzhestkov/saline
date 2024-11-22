import logging
import os
import pwd
import signal

from saline.config.parser import SalineCMDOptionParser


log = logging.getLogger(__name__)


class SalineCMD(SalineCMDOptionParser):
    """
    Create a Saline CMD tool
    """
    def run(self):
        pass