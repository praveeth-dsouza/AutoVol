import os
import random
import string
from Sample import SampleDump
import json
import logging

from Config.vol_path import STORE_PATH
from vol_command import execute_volatility_command
from pe_utils import static_analysis, get_strings


def get_workdir_path(malware_sample):
    return os.path.dirname(os.path.realpath(malware_sample.file_path))

def create_workdir():
    random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(16))
    target_directory = os.path.join(STORE_PATH,random_string)
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)
        logging.info('Created workdir at {}'.format(target_directory))
        return target_directory
    return None

def dump_process(memory_instance, pid, target_dump_dir, process_name=None, memdump=False):
    if process_name is None:
        process_name = 'unknown'

    if memdump:
        dump_method = 'memdump'
    else:
        pass
        dump_method = 'procdump'

    output = execute_volatility_command(memory_instance, dump_method,
                                        extra_flags='-p {} -D {}/'.format(pid, target_dump_dir), has_json_output=False)

    if memdump:
        src = os.path.join(target_dump_dir, str(pid) + ".dmp")
    else:
        src = os.path.join(target_dump_dir, "executable." + str(pid) + ".exe")

    if os.path.isfile(src):
        extension = '.dmp' if memdump else '._exe'
        target_dump_path = os.path.join(target_dump_dir, process_name + "." + str(pid) + extension)
        os.rename(src, target_dump_path)

        dump_obj = SampleDump(target_dump_path)
        dump_obj.calculate_hashes()

        with open(target_dump_path + '.strings.json', 'w') as strings_output_file:
            strings_output_file.write(json.dumps(get_strings(dump_obj), indent=4))

        if not memdump:
            with open(target_dump_path + '.static_analysis.json', 'w') as strings_output_file:
                strings_output_file.write(json.dumps(static_analysis(dump_obj), indent=4))

        logging.info('Dumping of process with pid {} succeeded'.format(pid))
        return True

def dump_dll(memory_instance, target_pid, image_base, target_dump_dir):
    output = execute_volatility_command(memory_instance, 'dlldump',
                                        extra_flags='-p {} -b {} -D {}/'.format(target_pid, image_base,
                                                                                target_dump_dir))
    logging.debug('Dumping DLL {}'.format(output))

    # IndexError if output 0 does not exists, because there was a problem with the dump
    try:
        if output[0]['Result'].startswith('OK'):
            status, module_dump_path = output[0]['Result'].split(':')
            src = os.path.join(target_dump_dir, module_dump_path.strip())
            if os.path.isfile(src):
                dst = os.path.join(target_dump_dir,
                                   'module.' + str(target_pid) + '.' + str(hex(output[0]['Module Base'])) + '.' + output[0][
                                       'Module Name'].replace('.', '_') + '.dll')
                os.rename(src, dst)
                logging.info('Saved as {}'.format(dst))

                dump_obj = SampleDump(dst)
                dump_obj.calculate_hashes()

                # Post processors on output...
                with open(dst + '.strings.json', 'w') as strings_output_file:
                    strings_output_file.write(json.dumps(get_strings(dump_obj),indent=4))

                with open(dst + '.static_analysis.json', 'w') as strings_output_file:
                    strings_output_file.write(json.dumps(static_analysis(dump_obj), indent=4))
    except IndexError:
        logging.warning('Problem dumping pid: {} at base: {}: {}'.format(target_pid,image_base,output))
        pass
