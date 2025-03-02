#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob
from itertools import groupby
from operator import itemgetter

from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery
from wazuh.wdb import WazuhDBConnection


# API field -> DB field
fields_translation_sca = {'policy_id': 'policy_id',
                          'name': 'name',
                          'description': 'description',
                          'references': '`references`',
                          'pass': 'pass',
                          'fail': 'fail',
                          'score': 'score',
                          'invalid': 'invalid',
                          'total_checks': 'total_checks',
                          'hash_file': 'hash_file',
                          'end_scan': "strftime('%Y-%m-%d %H:%M:%S', datetime(end_scan, 'unixepoch'))",
                          'start_scan': "strftime('%Y-%m-%d %H:%M:%S', datetime(start_scan, 'unixepoch'))"
                          }
fields_translation_sca_check = {'policy_id': 'policy_id',
                                'id': 'id',
                                'title': 'title',
                                'description': 'description',
                                'rationale': 'rationale',
                                'remediation': 'remediation',
                                'file': 'file',
                                'process': 'process',
                                'directory': 'directory',
                                'registry': 'registry',
                                'command': 'command',
                                'references': '`references`',
                                'result': 'result',
                                'status': '`status`',
                                'reason': 'reason'}
fields_translation_sca_check_compliance = {'compliance.key': 'key',
                                           'compliance.value': 'value'}
fields_translation_sca_check_rule = {'rules.type': 'type', 'rules.rule': 'rule'}

default_query_sca = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id'
default_query_sca_check = 'SELECT {0} FROM sca_check a LEFT JOIN sca_check_compliance b ON a.id=b.id_check LEFT JOIN sca_check_rules c ON a.id=c.id_check'


class WazuhDBQuerySCA(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count,
                 get_data, default_sort_field='policy_id', filters={}, fields=fields_translation_sca,
                 default_query=default_query_sca, count_field='policy_id'):
        self.agent_id = agent_id
        self._default_query_str = default_query
        self.count_field = count_field
        Agent(agent_id).get_basic_information()  # check if the agent exists

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='sca_policy', sort=sort,
                              search=search, select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, db_path=None,
                              min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'end_scan', 'start_scan'})
        self.conn = WazuhDBConnection()

    def _default_query(self):
        return self._default_query_str

    def _substitute_params(self):
        for k, v in self.request.items():
            self.query = self.query.replace(f':{k}', f"'{v}'")

    def _get_total_items(self):
        self._substitute_params()
        total_items = self.conn.execute(f'agent {self.agent_id} sql ' + self.query.format(self._default_count_query()))
        self.total_items = total_items if isinstance(total_items, int) else total_items[0][self._default_count_query()]

    def _default_count_query(self):
        return f"COUNT(DISTINCT {self.count_field})"

    def _get_data(self):
        self._substitute_params()
        self._data = self.conn.execute(f'agent {self.agent_id} sql '
                                       + self.query.format(','.join(map(lambda x: f"{self.fields[x]} as '{x}'",
                                                                        self.select['fields'] | self.min_select_fields)
                                                                    )
                                                           )
                                       )

    def _format_data_into_dictionary(self):
        return {"totalItems": self.total_items, "items": self._data}

    def _add_limit_to_query(self):
        if self.limit:
            if self.limit > common.maximum_database_limit:
                raise WazuhException(1405, str(self.limit))
            self.query += f' LIMIT {self.limit} OFFSET {self.offset}'
        elif self.limit == 0:  # 0 is not a valid limit
            raise WazuhException(1406)

    def run(self):

        self._add_select_to_query()
        self._add_filters_to_query()
        self._add_search_to_query()
        if self.count:
            self._get_total_items()
        self._add_sort_to_query()
        self._add_limit_to_query()
        if self.data:
            self._get_data()
            return self._format_data_into_dictionary()


def get_sca_list(agent_id=None, q="", offset=0, limit=common.database_limit,
                 sort=None, search=None, select=None, filters={}):
    """
    Gets a list of policies analized in the configuration assessment
    :param agent_id: agent id to get policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    if select is None:
        select = {'fields': list(fields_translation_sca.keys())}

    db_query = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                               select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()


def get_sca_checks(policy_id, agent_id=None, q="", offset=0, limit=common.database_limit,
                   sort=None, search=None, select=None, filters={}):
    """
    Gets a list of checks analized for a policy
    :param policy_id: policy id to get the checks from
    :param agent_id: agent id to get the policies from
    :param q: Defines query to filter in DB.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    fields_translation = {**fields_translation_sca_check,
                          **fields_translation_sca_check_compliance,
                          **fields_translation_sca_check_rule}

    full_select = {'fields': (list(fields_translation_sca_check.keys()) +
                              list(fields_translation_sca_check_compliance.keys()) +
                              list(fields_translation_sca_check_rule.keys())
                              )
                   }

    db_query = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                               select=full_select, count=True, get_data=True,
                               query=f"policy_id={policy_id}" if q == "" else f"policy_id={policy_id};{q}",
                               filters=filters, default_query=default_query_sca_check, default_sort_field='policy_id',
                               fields=fields_translation, count_field='id')

    result_dict = db_query.run()

    if 'items' in result_dict:
        checks = result_dict['items']
    else:
        raise WazuhException(2007)

    groups = groupby(checks, key=itemgetter('id'))
    result = []
    select_fields = full_select['fields'] if select is None else select['fields']
    select_fields = set([field if field != 'compliance' else 'compliance'
                         for field in select_fields if field in fields_translation_sca_check])
    # Rearrange check and compliance fields
    for _, group in groups:
        group_list = list(group)
        check_dict = {k: v for k, v in group_list[0].items()
                      if k in select_fields
                      }
        for extra_field, field_translations in [('compliance', fields_translation_sca_check_compliance),
                                                ('rules', fields_translation_sca_check_rule)]:
            if (select is None or extra_field in select['fields']) and set(field_translations.keys()) & group_list[0].keys():
                check_dict[extra_field] = [dict(zip(field_translations.values(), x))
                                           for x in set((map(itemgetter(*field_translations.keys()), group_list)))]

        result.append(check_dict)

    return {'totalItems': result_dict['totalItems'], 'items': result}
