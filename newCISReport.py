import copyreg
import re
from json import loads

from ipfabric import IPFClient
from ipfabric.tools import DeviceConfigs
from tabulate import tabulate
from ciscoconfparse import CiscoConfParse
from pydantic.dataclasses import dataclass
from typing import Optional
from copy import deepcopy
from collections import defaultdict


with open('cisco.json', 'r') as f:
    RULES = loads(f.read())


@dataclass
class Result:
    rule: Optional[str]
    desc: Optional[str]
    match: Optional[str] = ''
    section: Optional[str] = ''
    subsection: Optional[str] = ''
    config: Optional[str] = ''
    status: Optional[bool] = False
    exact: Optional[bool] = False
    reverse: Optional[bool] = False
    max: Optional[int] = 0
    min: Optional[int] = 0
    regex: Optional[str] = ''
    error: Optional[str] = ''

    def export(self):
        status = not self.status if self.reverse else self.status
        return {
            'status': 'PASS' if status else 'FAIL',
            'rule': self.rule,
            'description': self.desc,
            'match': self.match,
            'section': self.section,
            'config': self.config,
            'error': self.error
        }


def min_sec(obj, result: Result):
    value = obj.re_match_iter_typed(result.match)
    check = False
    if value:
        mins, secs = value.split(' ')
        secs = int(mins) * 60 + int(secs)
        check = True if secs <= result.max else False
    return check


def seconds(parse, result: Result):
    value = parse.re_match_iter_typed(result.match)
    check = False
    if value:
        check = True if int(value) <= result.max else False
    return check


def bpg_neighbor(obj, result: Result):
    matches = list()
    neighbors = defaultdict(list)
    childs = obj.re_search_children(result.subsection)
    neigh_regex = re.compile(r'^ neighbor ([\d\.]*) ')
    for child in childs:
        neigh = neigh_regex.match(child.text)
        neighbors[neigh.group(1)].append(child.text)

    for neighbor, config in neighbors.items():
        r = deepcopy(result)
        r.config = f'neighbor {neighbor}'
        for line in config:
            if re.search(r.match, line):
                r.status = True
                break
        matches.append(r)
    return matches


def section(parse: CiscoConfParse, result: Result):
    objs = parse.find_objects(result.section)
    if not objs:
        return [result]
    elif result.regex == 'interface':
        if len(objs) == 1:
            result.status = True
        else:
            result.config = f'{len(objs)} Loopback interfaces found.'
        return [result]

    matches = list()
    for obj in objs:
        r = deepcopy(result)
        if not r.match:
            r.status = True
        elif obj.has_children and r.regex == "%M %S":
            r.status = min_sec(obj, r)
            r.config = obj.text
        elif r.subsection:
            matches.extend(bpg_neighbor(obj, r))
            continue
        elif obj.has_children:
            r.status = True if obj.re_search_children(r.match) else False
            r.config = obj.text
        else:
            r.status = True if r.match in obj.text else False
            r.config = obj.text
        matches.append(r)
    return matches


def search_config(config):
    """
    A function to search for a specific list of string within the list of configuration files, only prints results.
    :param rules: list: List of rules to match
    :param config: str: Configuration of device
    :return:
    """
    parse = CiscoConfParse(config.splitlines(), syntax='ios', factory=True)
    matches = list()
    for rule, items in RULES.items():
        for item in items:
            result = Result(**item, rule=rule)
            if 'error' in item:
                matches.append(result)
            elif 'section' in item:
                matches.extend(section(parse, result))
            elif 'time' in item and item['time'] == "%S":
                result.status = seconds(parse, result)
                matches.append(result)
            else:
                result.status = True if parse.find_lines(result.match, exactmatch=result.exact) else False
                matches.append(result)
    return matches


def print_report(matches: list, verbose=True):
    if verbose:
        matches = [m.export() for m in matches]
    else:
        data = defaultdict(set)
        headers = dict()
        for result in matches:
            export = result.export()
            data[result.rule].add(export['status'])
            headers[result.rule] = {
                'rule': export['rule'],
                'description': export['description'],
                'error': export['error']
            }
        matches = list()
        for rule, status in data.items():
            tmp = dict()
            if len(status) == 1:
                tmp['status'] = status.pop()
            else:
                tmp['status'] = 'PARTIAL'
            tmp.update(headers[rule])
            matches.append(tmp)
    print(tabulate(matches, headers="keys"))


if __name__ == '__main__':
    # ipf = IPFClient()
    # cfg = DeviceConfigs(ipf)
    # # input_hostnames = ['L51AR21', 'L51EXR1']
    # input_hostnames = ['L51AR21']
    #
    #
    #
    # print('\n STARTING API script...')
    # for hostname in input_hostnames:
    #     config = cfg.get_configuration(hostname)
    #     if not config:
    #         continue
    #     print(hostname)
    #     search_config(rules, config.text)
    #     print()
    # print('\n ENDING API script with success...')

    with open('L51AR21.txt', 'r') as f:
        matches = search_config(f.read())
    print_report(matches, verbose=False)
