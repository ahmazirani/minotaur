import logging
import subprocess
from pdb import set_trace

from config import LOG_LEVEL


def get_logger(name):
    """
    Return pre-configured logger
    """
    logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    return logger


log = get_logger("utils")


def bash(command):

    log.debug("Running BASH command: %s", command)

    cmd = ['bash', '-c', command]

    return subprocess.check_output(cmd)


def bash_live(command):

    cmd = ['bash', '-c', command]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    while True:
        retcode = p.poll()
        line = p.stdout.readline()
        yield line
        if retcode is not None:
            break


def pick(gen, count):
    idx = 0
    if count > 0:
        for c in gen:
            idx += 1
            yield c
            if idx == count:
                break
