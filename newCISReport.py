import re
from json import loads

from ipfabric import IPFClient
from ipfabric.tools import DeviceConfigs
from tabulate import tabulate


def search_config(rules, config):
    """
    A function to search for a specific list of string within the list of configuration files, only prints results.
    :param rules: list: List of rules to match
    :param config: str: Configuration of device
    :return:
    """
    matches = list()
    for item in rules:
        if 'section' in item.keys():
            pattern = '(^{}.*$[\n\r]*(?:^\s.*$[\n\r]*)*)'.format(item['section'])
            regex = re.compile(pattern, re.MULTILINE)
            section = regex.search(config)
            check = 'OK' if section and item['match'] in section.group(0) else 'NOT'
            matches.append([check, item['code'], item['match'], item['section']])
        else:
            check = 'OK' if item['match'] in config else 'NOT'
            matches.append([check, item['code'], item['match']])
    print(tabulate(matches, headers=['Status', 'Rule', 'Config', 'Section']))


if __name__ == '__main__':
    ipf = IPFClient()
    cfg = DeviceConfigs(ipf)
    input_hostnames = ['L51AR21', 'L51EXR1']

    with open('rules/cisco.json', 'r') as f:
        rules = loads(f.read())

    print('\n STARTING API script...')
    for hostname in input_hostnames:
        config = cfg.get_configuration(hostname)
        if not config:
            continue
        print(hostname)
        search_config(rules, config.text)
        print()
    print('\n ENDING API script with success...')
