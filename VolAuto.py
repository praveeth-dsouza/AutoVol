import argparse
from profile import MemoryDump
from heuri import run_heuristics
from Utils.util import create_workdir
import os
import json
from validate_yara_rules import validate_yara_rules
import logging


parser = argparse.ArgumentParser()

parser.add_argument('-f', "--filename", help="The Executable you want to submit")
parser.add_argument('-m', action='store_true', help="Analyze a memory dump, use -f to specify the path")
parser.add_argument('--profile', help="Specify the profile, instead of having volatility detect it automaticly")
parser.add_argument('--dump', action='store_true', help="Dump suspicious executable and memory spaces from heuristics")
parser.add_argument('-r', action='store_true', help="Submit a directory, as opposed to -f (file)")

args = parser.parse_args()
print(args)

logging.basicConfig(filename='Volatility_Automation.log', level = logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if args.m:
    logging.info('Performing Memory Analysis')
    if args.filename:
        if args.r:
            logging.info('A folder was submitted')
            target_dir = args.filename
            for entry in os.scandir(target_dir):
                logging.info('Will analyze {}'.format(entry.path))
                if entry.is_file():
                    target_file = entry.path
                    memdump = MemoryDump(target_file)
                    if args.dump:
                        target_dir = create_workdir()
                    else:
                        target_dir = None

                    if args.profile is not None:
                        memdump.profile = args.profile
                    else:
                        memdump.identify_profile()

                    heuristics_results = run_heuristics(memdump, workdir=target_dir,dump_objects=args.dump)

                    # Save report to file
                    with open(os.path.join(target_dir, 'report.json'), 'w') as report:
                        report.write(json.dumps(heuristics_results, indent=4))
        else:
            logging.info('A single memory dump was submitted for processing')
            target_file = args.filename
            memdump = MemoryDump(target_file)

            if args.profile is not None:
                memdump.profile = args.profile
            else:
                memdump.identify_profile()

            target_dir = create_workdir()

            heuristics_results = run_heuristics(memdump, workdir=target_dir, dump_objects=args.dump)

            # Save report to file
            with open(os.path.join(target_dir, 'report.json'), 'w') as report:
                report.write(json.dumps(heuristics_results, indent=4))
    print("Validating Yara Rules")
    validate_yara_rules('./yara_rules','./report','pslist.json')
    print("Completed Validation")

