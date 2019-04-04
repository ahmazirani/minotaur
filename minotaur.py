#!/bin/env python3
import time

import datetime
import os
import sys
import argparse
from filepath.filepath import fp
from pdb import set_trace

from config import DATA_PATH
from flow import split_flows
from timeseries import extract_ts, par_extract_ts
from utils import get_logger
from analyze import analyze_flow_dir

log = get_logger("minotaur")


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', '-s', type=str, help='PCAP raw input file')
    parser.add_argument('--out', '-o', type=str, help='Output file/directory')
    parser.add_argument('--flows', '-f', type=str, help='Directory holding separated flow PCAPs')
    parser.add_argument('--analyze', '-a', type=str, help='Directory holding raw PCAPs')
    parser.add_argument('--analyzeflows', '-d', type=str, help='Directory holding separated PCAPs')
    parser.add_argument('--threads', '-j', type=int, help='Number of parallel threads to use')
    parser.add_argument('--timeseries', '-t', type=str, help='Extract time-series data from PCAPs. Expects '
                                                             'the given directory to be foldered into labels and '
                                                             'everything under each directory would be considered'
                                                             'in that label')
    return parser


def _main_flows(indir, outfile, args):
    if not args.threads:
        analyze_flow_dir(fp(indir), out_file=fp(outfile))
    else:
        analyze_flow_dir(fp(indir), out_file=fp(outfile), threads=args.threads)


def _main_analyze(args):
    start_time = time.time()

    in_dir = fp(args.analyze)

    if args.out:
        out_dir = fp(args.out)
    else:
        out_dir = DATA_PATH + fp(str(int(time.time())))

    out_dir.ensure()

    for f in in_dir.ls():
        log.info("separating flows in %s", f)
        flows_dir = out_dir + f.basename()
        split_flows(pcap=f, outdir=flows_dir)

        log.info("going through packets in %s", f)
        outfile = flows_dir + fp("flow_analysis_%d.json" % int(time.time() * 1000))
        _main_flows(flows_dir, outfile, args)

    end_time = time.time()
    log.info("run time: %d seconds (%s)", end_time - start_time, datetime.timedelta(seconds=end_time - start_time))


def _main_analyze_flows(args):

    start_time = time.time()
    in_dir = fp(args.analyzeflows)

    for f in in_dir.ls():
        log.info("going through packets in %s", f)
        outfile = f + fp("flow_analysis_%d.json" % int(time.time() * 1000))
        _main_flows(f, outfile, args)

    end_time = time.time()
    log.info("run time: %d seconds (%s)", end_time - start_time, datetime.timedelta(seconds=end_time - start_time))


def _main_timeseries(args):

    indir = fp(args.timeseries)
    if not indir.is_dir():
        log.error("No such directory '%s'" % args.timeseries)

    outdir = fp(args.out)
    outdir.ensure()

    par_extract_ts(indir, outdir)


def main(args):

    if args.analyze:
        _main_analyze(args)

    elif args.analyzeflows:
        _main_analyze_flows(args)

    elif args.split:
        split_flows(pcap=args.split, outdir=args.out)

    elif args.flows:
        _main_flows(args.flows, args.out, args)

    elif args.timeseries:
        _main_timeseries(args)

    else:
        create_parser().print_help()


if __name__ == "__main__":
    args = create_parser().parse_args()
    main(args)
