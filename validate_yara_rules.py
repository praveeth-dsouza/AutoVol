import yara
import json
import os
import datetime

INSTANCE_COUNT = 'instance_count'
PARENT_COUNT = 'parent_count'
CHILD_COUNT = 'child_count'
SVCHOST_EXE = 'svchost.exe'
SYSTEM = "system"
SMSS_EXE = "smss.exe"
SERVICES_EXE = "services.exe"
WIN_INIT_EXE = "wininit.exe"
LSASS_EXE = "lsass.exe"
TASK_HOST_W_EXE = "taskhostw.exe"
RUNTIME_BROKER_EXE = "runtimebroker.exe"
WIN_LOGON_EXE = "winlogon.exe"
LSA_ISO_EXE = "lsaiso.exe"
IS_PARENT_A_SYSTEM_PROCESS = 'is_parent_a_system_process'
EMPTY_STRING = ""
IS_PARENT_VALID = "is_parent_valid"
PASSED = 'PASSED'
FAILED = 'FAILED'
TEXT_FORMAT = '.txt'
EXE_EXTENSION = '.exe'
NEW_LINE = '\n'

def load_data(file_path):
    with open(file_path) as f:
        return json.load(f)

def instance_count_for_process(process_information, process_name):
    rows = process_information['rows']
    system_process_count = len(list(filter(lambda x: x[1].lower() == process_name, rows)))
    if not system_process_count:
        print("Process is Not Available : ",process_name)
    return system_process_count

def process_child_count(process_information, process_name):
    rows = process_information['rows']
    record = list(filter(lambda x: x[1].lower() == process_name, rows))
    pid = 0
    if len(record)!=0:
        pid = record[0][2]
        system_process_children = len(list(filter(lambda x : x[3] == pid, rows)))
    else:
        print("There are no Child for this process: ", process_name)
        system_process_children = 0
    return system_process_children

def is_process_parent_is_valid(process_information, process_name, parent_name):
    rows = process_information['rows']
    record = list(filter(lambda x: x[1].lower() == process_name, rows))
    ppid = 0
    if len(record)!= 0 and parent_name != None:
        ppid = record[0][3] 
        parent_process_list = list(filter(lambda x : x[2] == ppid, rows))
        if len(parent_process_list) == 0:
            parent_name_found = None
        else:
            parent_name_found = parent_process_list[0][1].lower()
        return parent_name_found == parent_name
    else:
        print("Given process is not available: ", process_name)
        return False


def validate_rule(rule_file, rule, process_information, parent=None):
    yara_rule = yara.compile(rule_file,
                        externals = {INSTANCE_COUNT : 0, PARENT_COUNT : 0, CHILD_COUNT : 0, IS_PARENT_VALID: False})
    process_name = 'system' if rule == SYSTEM else rule+EXE_EXTENSION
    parent_process_name = 'system' if parent == SYSTEM else (None if parent == None else parent+EXE_EXTENSION)
    result = yara_rule.match(data=EMPTY_STRING, externals={IS_PARENT_VALID: is_process_parent_is_valid(
            process_information, process_name, parent_process_name),
            INSTANCE_COUNT: instance_count_for_process(process_information, process_name),
            CHILD_COUNT: process_child_count(process_information, process_name)})

    return False if len(result) == 0 else True

def generate_report(report_file, rule_name, is_rule_passed):
    with open(report_file, 'a+') as f:
        to_write = rule_name+"(PASSED/FAILED) : "+(PASSED if is_rule_passed else FAILED)  + NEW_LINE
        f.write(to_write)

def get_process_parent_process_name(rule_name):
    process_list = rule_name.split('-')
    if len(process_list) == 2:
        return process_list[0].lower(), process_list[1].lower()
    else:
        return process_list[0], None


def validate_yara_rules(rules_folder_path, report_generation_path, pslist_file_path):
    files_list = os.listdir(rules_folder_path)
    process_information = load_data(pslist_file_path)
    final_report = 'yara_report_'+datetime.datetime.now().strftime('%d-%m-%Y_%H_%M')+TEXT_FORMAT
    for rule in files_list:
        rule_parent_name = rule[:rule.find('_rule')]
        process_name, parent_process = get_process_parent_process_name(rule_parent_name)
        result = validate_rule(rules_folder_path + '//'+rule, process_name, process_information, parent_process)
        generate_report(report_generation_path+'//'+final_report,
                        process_name, result)


