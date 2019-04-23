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


def get_src_dst(cap):
    """
    return the peers of a flow a
    :param cap: flow PCAP file parsed as FileCapture
    :return: tuple of two strings
    """

    if not isinstance(cap, psh.FileCapture):
        raise Exception("Illegal argument type: %s" % type(cap))

    pkt = get_base_pkt(cap)

    if hasattr(pkt, "ip"):
        if hasattr(pkt, "tcp"):
            first = pkt.ip.dst_host + "#" + pkt.tcp.dstport
            second = pkt.ip.src_host + "#" + pkt.tcp.srcport
            if pkt.tcp.dstport == 443 or pkt.tcp.dstport == 80:
                return first, second
            else:
                return second, first
        elif hasattr(pkt, "udp"):
            return pkt.ip.dst_host + "#" + pkt.udp.dstport, pkt.ip.src_host + "#" + pkt.udp.srcport
        else:
            return pkt.ip.dst_host + "#0", pkt.ip.src_host + "#0"
    elif hasattr(pkt, "eth"):
        return pkt.eth.dst, pkt.eth.src
    else:
        return "N/A", "N/A"


def get_base_pkt(cap):
    for pkt in cap:
        if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'tcp'):
            return pkt
    return cap[0]


def analyze_flow(pcap):
    """
    :param pcap: file-path to flow PCAP file
    """

    log.debug("parsing flow file: %s", pcap)

    has_http2 = False
    has_https = False

    cap = psh.FileCapture(pcap.path())

    count = 0

    for p in cap:
        if hasattr(p, "ssl") and hasattr(p.ssl, "record"):
            if not has_http2 and ("http2" in p.ssl.record):
                has_http2 = True
            elif not has_https and ("http-over-tls" in p.ssl.record):
                has_https = True
        count += 1

    h1, h2 = get_src_dst(cap)

    res = {
        "http2": has_http2,
        "https": has_https,
        "h1": h1,
        "h2": h2,
        "packets": count,
        "size": os.path.getsize(pcap.path())
    }

    cap.close()

    log.debug("results: %s", res)

    return res


def _analyze_map(pcap):
    return pcap.path(), analyze_flow(pcap)


def analyze_flow_dir(pcaps_dir, out_file=None, threads=8):
    """
    :param threads: Num threads to use
    :param pcaps_dir: Flow-separated PCAPs file-path -> FilePath
    :param out_file:
    :return: dict holding info
    """

    # resort to default value
    if isinstance(out_file, str):
        out_file = fp(out_file)
    out_file = out_file or (DATA_PATH + fp("flow_analysis_%d.json" % int(time.time())))

    # initiate pool
    pool = multi.Pool(processes=threads)
    map_res = []

    # run async and show progress
    files = list(pcaps_dir.find_files())
    for x in tqdm.tqdm(pool.imap_unordered(_analyze_map, files), total=len(files)):
        map_res.append(x)

    # retrieve results
    data = dict(map_res)

    # close pool
    pool.close()
    pool.join()

    # write to file
    log.info("writing final JSON result to %s", out_file)
    with out_file.open(mode='w') as f:
        json.dump(data, f)

    return data


if __name__ == "__main__":
    analyze_flow(fp("data/flow/421/2265850585-20160914161654_0.pcap"))
