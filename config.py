
import os
from filepath.filepath import fp
from os.path import join, dirname, abspath

_BASE_PATH = fp(dirname(abspath(__file__)))

DATA_PATH = _BASE_PATH + fp("data")

