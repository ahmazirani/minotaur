#!/bin/env python3

import os
import sys
import argparse
from filepath.filepath import fp
from pdb import set_trace

from flow import split_flows
from utils import get_logger
from analyze import analyze_flow_dir

log = get_logger("minotaur")


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', '-s', type=str, help='PCAP raw input file')
    parser.add_argument('--out', '-o', type=str, help='Output file/directory')
    parser.add_argument('--flows', '-f', type=str, help='Directory holding separated flow PCAPs')
    parser.add_argument('--threads', type=int, help='Number of parallel threads to use')
    return parser


def main(args):
    if args.split:
        split_flows(pcap=args.read, outdir=args.out)
    elif args.flows:
        if not args.threads:
            analyze_flow_dir(fp(args.flows), out_file=args.out)
        else:
            analyze_flow_dir(fp(args.flows), out_file=args.out, threads=args.threads)
    else:
        create_parser().print_help()


if __name__ == "__main__":
    args = create_parser().parse_args()
    main(args)


