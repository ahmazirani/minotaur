import time

from pdb import set_trace

from filepath.filepath import fp, SortOrder
from uuid import uuid4

from utils import get_logger, pick
from analyze import get_src_dst
from config import FEATURE_SIZE, NUM_CORES

import pyshark as psh


log = get_logger("time-series")


def extract_ts(indir, outdir, threads=None):
    """
    Extract time-series from label-directory PCAP corpus
    :param indir: PCAP corpus organized with each 1st-level dir representing the label -> FilePath
    :param outdir: output time-series files -> FilePath
    :return:
    """

    threads = threads or NUM_CORES

    uuid = "%x" % int(time.time())

    x1_file = outdir + fp("data_x_size_" + uuid + ".csv")
    x2_file = outdir + fp("data_x_dir_" + uuid + ".csv")
    y_file = outdir + fp("data_y_" + uuid + ".csv")
    log_file = outdir + fp("log_" + uuid + ".txt")

    with x1_file.open(mode='w') as x1f, x2_file.open(mode='w') as x2f, \
            y_file.open(mode='w') as yf, log_file.open(mode='w') as logf:

        label = 0

        for dir in indir.ls(order=SortOrder.ALPHA):

            label += 1

            log.info("Calling %s label %d", dir.basename(), label)
            logf.write("Label: %s -> %d\n" % (dir.basename(), label))

            for f in dir.find_files():
                if f.is_file() and f.ext() not in ["json", "csv", "txt"]:
                    sizes, dirs = _extract_ts_file(f)
                    if sizes and dirs:
                        x1f.write(",".join(sizes) + "\n")
                        x2f.write(",".join(dirs) + "\n")
                        yf.write(str(label) + "\n")


def _fix_length(iterable, value='0'):
    arr = list(pick(iterable, FEATURE_SIZE))
    return arr + [value] * max(0, FEATURE_SIZE - len(arr))


def _extract_ts_file(infile):
    """
    Extract feature vectors for given flow file
    :param infile: flow PCAP file -> FilePath
    :return:
    """

    cap = psh.FileCapture(infile.path())

    src, dst = get_src_dst(cap)

    if ":" not in src:
        return None, None

    [src_ip, src_port] = src.split(":")

    direction = _fix_length((str(pkt.captured_length) for pkt in cap))
    packet_size = _fix_length(('1' if (pkt.tcp.srcport, pkt.ip.src_host) == (src_port, src_ip) else '-1'
                               for pkt in cap))

    return packet_size, direction



