import re
from json import loads

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
    match: Optional[str] = None
    section: Optional[str] = None
    subsection: Optional[str] = None
    config: Optional[str] = None
    status: Optional[bool] = False
    exact: Optional[bool] = False
    reverse: Optional[bool] = False
    max: Optional[int] = 0
    min: Optional[int] = 0
    regex: Optional[str] = None
    error: Optional[str] = None
    status_name: Optional[str] = None
    check_section: Optional[str] = None
    acl: Optional[bool] = False

    def export(self):
        if self.status_name:
            status_name = self.status_name
        else:
            status = not self.status if self.reverse else self.status
            status_name = 'PASS' if status else 'FAIL'
        return {
            'status': status_name,
            'rule': self.rule,
            'description': self.desc,
            'match': self.match,
            'section': self.section,
            'config': self.config,
            'error': self.error
        }


class CISReport:
    def __init__(self, config):
        self.config = config
        self.parse = CiscoConfParse(self.config.splitlines(), syntax='ios', factory=True)
        self.results = list()

    def search_config(self):
        """
        A function to search for a specific list of string within the list of configuration files, only prints results.
        :param rules: list: List of rules to match
        :param config: str: Configuration of device
        :return:
        """
        for rule, items in RULES.items():
            for item in items:
                result = Result(**item, rule=rule)
                if result.check_section:
                    objs = self.parse.find_objects(result.check_section)
                    if not objs:
                        result.status_name = 'N/A'
                        self.results.append(result)
                        continue
                if 'error' in item:
                    result.status_name = 'MANUAL'
                    self.results.append(result)
                elif 'section' in item:
                    self.section(result)
                elif 'time' in item and item['time'] == "%S":
                    result.status = self.seconds(result)
                    self.results.append(result)
                else:
                    result.status = True if self.parse.find_lines(result.match, exactmatch=result.exact) else False
                    self.results.append(result)

    def section(self, result: Result):
        objs = self.parse.find_objects(result.section)
        if not objs:
            self.results.append(result)
        elif result.acl:
            self.search_acl(objs, result)
        elif result.regex == 'interface':
            if len(objs) == 1:
                result.status = True
            else:
                result.config = f'{len(objs)} Loopback interfaces found.'
            self.results.append(result)
        else:
            self.search_objs(objs, result)

    def seconds(self, result: Result):
        value = self.parse.re_match_iter_typed(result.match)
        check = False
        if value:
            check = True if int(value) <= result.max else False
        return check

    def search_acl(self, objs, result: Result):
        for obj in objs:
            r = deepcopy(result)
            if obj.has_children:
                value = obj.re_search_children(result.match)
            else:
                value = re.match(r.match, obj.text)
            if value:
                if isinstance(value, re.Match):
                    acl = value.group(1)
                else:
                    acl = re.search(r.match, value[0].text).group(1)
                try:
                    acls = self.parse.find_objects(f"^access-list {int(acl)} ")
                except ValueError:
                    acls = self.parse.find_objects(f"^ip access-list (extended|standard) {acl}$")
                if acls:
                    r.config = f"access-list {acl}"
                    r.status = True
                else:
                    r.config = f"MISSING access-list {acl}"
            else:
                r.config = obj.text
            self.results.append(r)

    def search_objs(self, objs, result: Result):
        for obj in objs:
            r = deepcopy(result)
            if not r.match:
                r.status = True
            elif obj.has_children and r.regex == "%M %S":
                r.status = self.min_sec(obj, r)
                r.config = obj.text
            elif r.subsection:
                self.bpg_neighbor(obj, r)
                continue
            elif obj.has_children:
                r.status = True if obj.re_search_children(r.match) else False
                r.config = obj.text
            else:
                r.status = True if r.match in obj.text else False
                r.config = obj.text
            self.results.append(r)

    def bpg_neighbor(self, obj, result: Result):
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
            self.results.append(r)

    @staticmethod
    def min_sec(obj, result: Result):
        value = obj.re_match_iter_typed(result.match)
        check = False
        if value:
            mins, secs = value.split(' ')
            secs = int(mins) * 60 + int(secs)
            check = True if secs <= result.max else False
        return check

    def print_report(self, verbose=True):
        if verbose:
            matches = [m.export() for m in self.results]
        else:
            data = defaultdict(set)
            headers = dict()
            for result in self.results:
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
