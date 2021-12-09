from json import loads

from ipfabric import IPFClient
from ipfabric.tools import DeviceConfigs
from tabulate import tabulate
from ciscoconfparse import CiscoConfParse
from pydantic.dataclasses import dataclass
from typing import Optional
from copy import deepcopy


with open('cisco.json', 'r') as f:
    RULES = loads(f.read())


@dataclass
class Result:
    rule: Optional[str]
    desc: Optional[str]
    match: Optional[str] = ''
    section: Optional[str] = ''
    config: Optional[str] = ''
    status: Optional[bool] = False
    exact: Optional[bool] = False
    reverse: Optional[bool] = False
    max: Optional[int] = 0
    min: Optional[int] = 0
    time: Optional[str] = ''


def min_sec(obj, result: Result):
    value = obj.re_match_iter_typed(result.match)
    if value:
        mins, secs = value.split(' ')
        secs = int(mins) * 60 + int(secs)
        check = True if secs <= result.max else False
    else:
        check = False
    return check


def seconds(parse, result: Result):
    value = parse.re_match_iter_typed(result.match)
    if value:
        check = True if int(value) <= result.max else False
    else:
        check = False
    return check


def section(parse: CiscoConfParse, result: Result):
    objs = parse.find_objects(result.section)
    if not objs:
        result.status = False
        return [result]

    matches = list()
    for obj in objs:
        r = deepcopy(result)
        if not r.match:
            r.status = True
        elif obj.has_children and r.time == "%M %S":
            r.status = min_sec(obj, r)
            r.config = obj.text
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
            if 'section' in item.keys():
                matches.extend(section(parse, result))
            elif 'time' in item and item['time'] == "%S":
                result.status = seconds(parse, result)
                matches.append(result)
            else:
                result.status = True if parse.find_lines(result.match, exactmatch=result.exact) else False
                matches.append(result)
    print(tabulate([m.__dict__ for m in matches], headers="keys"))


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
        search_config(f.read())
