
import os
from filepath.filepath import fp
from os.path import join, dirname, abspath
from logging import INFO

_BASE_PATH = fp(dirname(abspath(__file__)))

DATA_PATH = _BASE_PATH + fp("data")

LOG_LEVEL = INFO

FEATURE_SIZE = 30

NUM_CORES = 4
