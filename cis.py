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


class RuleHeaders:
    def __init__(self):
        self.headers = [('1', 'Management Plane'),
                        ('1.1', 'Local Authentication, Authorization and Accounting (AAA) Rules'),
                        ('1.2', 'Access Rules'), ('1.3', 'Banner Rules'), ('1.4', 'Password Rules'),
                        ('1.5', 'SNMP Rules'), ('1.6', 'Login Enhancements'), ('2', 'Control Plane'),
                        ('2.1', 'Global Service Rules'), ('2.1.1', 'Setup SSH'),
                        ('2.1.1.1', 'Configure Prerequisites for the SSH Service'), ('2.2', 'Logging Rules'),
                        ('2.3', 'NTP Rules'), ('2.3.1', 'Require Encryption Keys for NTP'), ('2.4', 'Loopback Rules'),
                        ('3', 'Data Plane'), ('3.1', 'Routing Rules'), ('3.2', 'Border Router Filtering'),
                        ('3.3', 'Neighbor Authentication'),
                        ('3.3.1', 'Require EIGRP Authentication if Protocol is Used'),
                        ('3.3.2', 'Require OSPF Authentication if Protocol is Used'),
                        ('3.3.3', 'Require RIPv2 Authentication if Protocol is Used'),
                        ('3.3.4', 'Require BGP Authentication if Protocol is Used')]


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
        :return:
        """
        for rule, items in RULES.items():
            for item in items:
                self._check_rules(item, rule)
        return [m.export() for m in self.results]

    def _check_rules(self, item, rule):
        result = Result(**item, rule=rule)
        if self._check_na(result):
            return
        if 'error' in item:
            result.status_name = 'MANUAL'
            self.results.append(result)
        elif 'section' in item:
            self._section(result)
        elif 'time' in item and item['time'] == "%S":
            result.status = self._seconds(result)
            self.results.append(result)
        else:
            result.status = True if self.parse.find_lines(result.match, exactmatch=result.exact) else False
            self.results.append(result)

    def _check_na(self, result):
        if result.check_section:
            objs = self.parse.find_objects(result.check_section)
            if not objs:
                result.status_name = 'N/A'
                self.results.append(result)
                return True
        return False

    def _section(self, result: Result):
        objs = self.parse.find_objects(result.section)
        if not objs:
            self.results.append(result)
        elif result.acl:
            self._search_acl(objs, result)
        elif result.regex == 'interface':
            if len(objs) == 1:
                result.status = True
            else:
                result.config = f'{len(objs)} Loopback interfaces found.'
            self.results.append(result)
        else:
            self._search_objs(objs, result)

    def _seconds(self, result: Result):
        value = self.parse.re_match_iter_typed(result.match)
        check = False
        if value:
            check = True if int(value) <= result.max else False
        return check

    def _search_acl(self, objs, result: Result):
        for obj in objs:
            r = deepcopy(result)
            if obj.has_children:
                value = obj.re_search_children(result.match)
            else:
                value = re.match(r.match, obj.text)
            if value:
                r = self._find_acl(value, r)
            else:
                r.config = obj.text
            self.results.append(r)

    def _find_acl(self, value, r):
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
        return r

    def _search_objs(self, objs, result: Result):
        for obj in objs:
            r = deepcopy(result)
            if not r.match:
                r.status = True
            elif obj.has_children and r.regex == "%M %S":
                r.status = self._min_sec(obj, r)
                r.config = obj.text
            elif r.subsection:
                self._bpg_neighbor(obj, r)
                continue
            elif obj.has_children:
                r.status = True if obj.re_search_children(r.match) else False
                r.config = obj.text
            else:
                r.status = True if r.match in obj.text else False
                r.config = obj.text
            self.results.append(r)

    def _bpg_neighbor(self, obj, result: Result):
        neighbors = defaultdict(list)
        childs = obj.re_search_children(result.subsection)
        neigh_regex = re.compile(r'^ neighbor ([\d.]*) ')
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
    def _min_sec(obj, result: Result):
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
        matches = self._print_report_headers(matches)
        print(tabulate(matches, headers="keys"))

    @staticmethod
    def _print_report_headers(matches):
        headers = RuleHeaders()
        formatted = list()
        nxt = headers.headers.pop(0)
        formatted.append({'status': '-' * sum(c.isdigit() for c in nxt[0]), 'rule': nxt[0], 'description': nxt[1]})
        nxt = headers.headers.pop(0)
        for match in matches:
            while nxt[0] and re.search(f"^{nxt[0]}", match['rule']):
                formatted.append({'status': '-' * sum(c.isdigit() for c in nxt[0]),
                                  'rule': nxt[0], 'description': nxt[1]})
                try:
                    nxt = headers.headers.pop(0)
                except IndexError:
                    nxt = (None, None)
            formatted.append(match)
        return formatted
