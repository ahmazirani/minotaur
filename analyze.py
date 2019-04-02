import os
import time
import multiprocessing as multi

import json
import pyshark as psh
import tqdm
from filepath.filepath import fp

from utils import get_logger
from config import DATA_PATH


log = get_logger("analyze")


def analyze_flow(pcap):
    """
    :param pcap: file-path to flow PCAP file
    """

    log.info("parsing flow file: %s", pcap)

    has_http2 = False
    has_https = False

    cap = psh.FileCapture(pcap.path())

    count = 0

    for p in cap:
        if hasattr(p, "ssl") and hasattr(p.ssl, "record"):
            if "http2" in p.ssl.record:
                has_http2 = True
            elif "http-over-tls" in p.ssl.record:
                has_https = True
        count += 1

    pkt = cap[0]

    res = {
        "http2": has_http2,
        "https": has_https,
        "h1": pkt.ip.dst_host + ":" + pkt.tcp.dstport,
        "h2": pkt.ip.src_host + ":" + pkt.tcp.srcport,
        "packets": count,
        "size": os.path.getsize(pcap.path())
    }

    cap.close()

    log.info("results: %s", res)

    return res


def _analyze_map(pcap):
    return pcap.path(), analyze_flow(pcap)


def analyze_flow_dir(pcaps_dir, out_file=None, threads=8):
    """
    :param pcaps_dir: Flow-separated PCAPs file-path
    :param out_file:
    :return: dict holding info
    """
    # resort to default value
    if isinstance(out_file, str):
        out_file = fp(out_file)
    out_file = out_file or DATA_PATH + fp("flow_analysis_%d.txt" % int(time.time()))

    # initiate pool
    pool = multi.Pool(processes=threads)
    map_res = []
    # rs = pool.map_async(_analyze_map, pcaps_dir.find_files(), callback=map_res.append)

    # run async and show progress
    files = list(pcaps_dir.find_files())
    for x in tqdm.tqdm(pool.imap_unordered(_analyze_map, files), total=len(files)):
        map_res.append(x)

    # while True:
    #
    #     if rs.ready():
    #         break
    #
    #     remaining = rs._number_left
    #
    #     log.info("==========================================")
    #     log.info(" %d tasks completed", len(map_res))
    #     log.info("==========================================")
    #
    #     time.sleep(1)

    # retrieve results
    data = dict(map_res)

    # close pool
    pool.close()
    pool.join()

    # write to file
    with out_file.open(mode='w') as f:
        json.dump(data, f)

    return data


if __name__ == "__main__":
    analyze_flow(fp("data/flow/421/2265850585-20160914161654_0.pcap"))
