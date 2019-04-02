from filepath.filepath import fp
from pdb import set_trace

from utils import bash, get_logger
import config as cnf

log = get_logger("flow")


def split_flows(pcap, outdir=None):

    outdir = fp(outdir) if outdir else cnf.DATA_PATH
    outfile = outdir + fp("out.data")
    outdir.ensure()

    log.info("Saving flow-separated PCAPs to {}".format(outdir))

    bash(""" yaf -i "{input}" --pcap-per-flow --pcap """
         """{out_dir} -o {out} --max-payload 10000000 """
         .format(input=pcap, out_dir=outdir.path(), out=outfile.path()))
