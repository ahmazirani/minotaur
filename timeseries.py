import sys
import time
import math

from pdb import set_trace

from filepath.filepath import fp, SortOrder
from uuid import uuid4

from utils import get_logger, pick, bash
from analyze import get_src_dst
from config import FEATURE_SIZE, NUM_CORES

import pyshark as psh
import multiprocessing as mp


log = get_logger("time-series")


def _worker_main_loop(id, data_arr, function, *outfiles):

    # open out files
    file_pointers = [open(f.path(), 'w') for f in outfiles]

    total = len(data_arr)
    logperiod = min(_round(total/20), 2000)

    # iterate into data aka tasks
    for i, d in enumerate(data_arr):

        # run the task
        res = function(d)

        # write outputs
        for i, r in enumerate(res):
            log.debug("writing to %s", file_pointers[i])
            file_pointers[i].write(",".join(r) + "\n")

        # log every now and then
        if i + 1 % logperiod == 0:
            log.info("===================")
            log.info("worker %d at %.2f%%", id, 100*i/total)
            log.info("===================")

    # close out files
    for f in file_pointers:
        f.close()


def _round(f):
    return int(math.floor(f) if f % 1 <= 0.5 else math.ceil(f))


def _split_arr(arr, parts):
    res = []
    size = _round(len(arr) / parts)
    for i in range(parts - 1):
        res.append(arr[i*size:(i+1)*size])
    res.append(arr[(parts - 1) * size:])
    return res


def _map_function(bundle):
    i, d, f, o = bundle
    _worker_main_loop(i, d, f, *o)


def _launch_pool(all_data, function, get_outfiles_for_worker, workers):

    pool = mp.Pool(processes=workers)
    splitted_data = _split_arr(all_data, workers)
    map_func_inputs = [(i, d, function, get_outfiles_for_worker(i)) for i, d in enumerate(splitted_data)]

    pool.map(_map_function, map_func_inputs)


def _extract_ts(bundle):
    pcap_file, label = bundle
    extracted_info = _extract_ts_file(pcap_file)
    return extracted_info[0], extracted_info[1], [str(label)]


def par_extract_ts(indir, outdir, threads=None):

    threads = threads or NUM_CORES

    uuid = "%x" % int(time.time())

    in_data = [(f, label) for label, dir in enumerate(indir.ls(order=SortOrder.ALPHA))
               for f in dir.find_files()
               if f.is_file() and f.ext() not in ["json", "csv", "txt"]]

    _launch_pool(
        in_data,
        _extract_ts,
        lambda n: [
            (outdir + fp(file_name)) for file_name in [
                "{uuid}_{name}_{worker}.csv".format(uuid=uuid, name=dname, worker=n) for dname in ["x1", "x2", "y"]
            ]
        ],
        threads
    )

    merge_and_clean(outdir, uuid)


def merge_and_clean(outdir, uuid):
    for name in ("x1", "x2", "y"):
        bash("cat {outdir}/{uuid}_{name}_*.csv >> {outdir}/{uuid}_{name}.csv".format(uuid=uuid, name=name, outdir=outdir))
        bash("rm {outdir}/{uuid}_{name}_*.csv".format(uuid=uuid, name=name, outdir=outdir))


def extract_ts(indir, outdir):
    """
    Extract time-series from label-directory PCAP corpus
    :param indir: PCAP corpus organized with each 1st-level dir representing the label -> FilePath
    :param outdir: output time-series files -> FilePath
    :return:
    """

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


if __name__ == "__main__":
    merge_and_clean(fp(sys.argv[1]), "5ca63126")


