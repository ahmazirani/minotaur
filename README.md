Minotaur
=======


![Minotaur](https://www.streamfinancial.com.au/wp-content/uploads/2015/02/THESEUS_AND_THE_MINOTAUR_by_aka_maelstrom.jpg)

Usage:

```
usage: minotaur.py [-h] [--split SPLIT] [--out OUT] [--flows FLOWS]
                   [--analyze ANALYZE] [--analyzeflows ANALYZEFLOWS]
                   [--threads THREADS] [--timeseries TIMESERIES]

optional arguments:
  -h, --help            show this help message and exit
  --split SPLIT, -s SPLIT
                        PCAP raw input file
  --out OUT, -o OUT     Output file/directory
  --flows FLOWS, -f FLOWS
                        Directory holding separated flow PCAPs
  --analyze ANALYZE, -a ANALYZE
                        Directory holding raw PCAPs
  --analyzeflows ANALYZEFLOWS, -d ANALYZEFLOWS
                        Directory holding separated PCAPs
  --threads THREADS, -j THREADS
                        Number of parallel threads to use
  --timeseries TIMESERIES, -t TIMESERIES
                        Extract time-series data from PCAPs. Expects the given
                        directory to be foldered into labels and everything
                        under each directory would be consideredin that label

```
