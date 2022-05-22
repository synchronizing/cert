__author__ = "Felipe Faria"

import pathlib
import appdirs

__data__ = pathlib.Path(appdirs.user_data_dir(__package__, __author__))

from .connection import *
from .crypto import *
