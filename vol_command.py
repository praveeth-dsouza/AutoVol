from Config.vol_path import VOLATILITY_PATH
import json
import os
import random
import string


def execute_volatility_command(memory_instance, plugin_name, extra_flags=None, has_json_output=True):

    profile = memory_instance.profile
    memory_path = memory_instance.memory_path

    command = '{} --profile {} -f "{}" {} '.format(VOLATILITY_PATH, profile, memory_path, plugin_name)

    # If the command has additional flags, add them here
    if extra_flags is not None:
        command += extra_flags + ' '

    # If the command has json output, add the output flag
    if plugin_name == 'dlldump':
        letters = string.digits
        ran_dig = ''.join(random.choice(letters) for i in range(10))
        if has_json_output:
            command += '--output=json '
            command += '--output-file=' + './Store/'+plugin_name+str(ran_dig) + '.json'
    else:
        if has_json_output:
            command += '--output=json '
            command += '--output-file=' + plugin_name + '.json'
    print(command)
    os.system(command)

    if (plugin_name == 'memdump' or plugin_name == 'procdump' or plugin_name == 'malfind'):
        return None
    elif(plugin_name == 'dlldump'):
        with open('./Store/'+plugin_name+str(ran_dig)+'.json','r') as f:
            data = json.load(f)
        final_output =[]
        for row in data['rows']:
            entry = dict()
            for column_index, parameter in enumerate(row):
                entry[data['columns'][column_index]] = parameter
            final_output.append(entry)
        return final_output
    else:

        with open(plugin_name+'.json','r') as f:
            data = json.load(f)
        final_output =[]
        for row in data['rows']:
            entry = dict()
            for column_index, parameter in enumerate(row):
                entry[data['columns'][column_index]] = parameter
            final_output.append(entry)
        return final_output
