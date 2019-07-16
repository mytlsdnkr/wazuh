

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime
from glob import glob
from operator import itemgetter

from wazuh import common, Connection
from wazuh.agent import Agent
from wazuh.core import syscheck
from wazuh.exception import WazuhInternalError, WazuhError
from wazuh.rbac import matches_privileges
from wazuh.utils import WazuhVersion


@matches_privileges(actions=['syscheck:put'], resources='agent:id:{agent_id}')
def run(agent_id=None):
    """
    Runs rootcheck and syscheck in an agent

    :param agent_id: Agent ID.
    :return: Message.
    """
    if agent_id == '000':
        ret_msg = syscheck.restart_local()
    else:
        # Check if agent exists
        agent_info = Agent(agent_id).get_basic_information()
        if 'status' in agent_info:
            agent_status = agent_info['status']
        else:
            agent_status = "N/A"
        if agent_status.lower() != 'active':
            raise WazuhInternalError(1601, extra_message='{0} - {1}'.format(agent_id, agent_status))

        # Run scan in agent
        ret_msg = syscheck.restart(agent_id=agent_id)

    return ret_msg


@matches_privileges(actions=['syscheck:put'], resources='agent:id:*')
def run_all():
    """
    Runs syscheck/rootcheck in all agents

    :return: Message.
    """
    # Run scan in agent 000
    syscheck.restart_local()

    # Run scan in all agents
    ret_msg = syscheck.restart()

    return ret_msg


@matches_privileges(actions=['syscheck:delete'], resources='agent:id:{agent_id}')
def clear(agent_id=None):
    """
    Clears the syscheck database of the agent.

    :param agent_id: Agent ID.
    :return: Message.
    """

    return syscheck.clear(agent_id)


@matches_privileges(actions=['syscheck:delete'], resources='agent:id:*')
def clear_all():
    """
    Clears the syscheck database of all agents.

    :return: Message.
    """
    agents = map(itemgetter('id'), Agent.get_agents_overview(select=['id'])['items'])
    for agent_id in agents:
        syscheck.clear(agent_id)

    return "Syscheck databases deleted"


@matches_privileges(actions=['syscheck:get'], resources='agent:id:{agent_id}')
def last_scan(agent_id=None):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    # Pre-processing
    my_agent = Agent(agent_id)
    try:
        agent_version = my_agent.get_basic_information(select=['version'])['version']
    except KeyError:
        # If the agent is never connected, it won't have either version (key error) or last scan information.
        return {'start': None, 'end': None}

    # Processing
    if WazuhVersion(agent_version) < WazuhVersion('Wazuh v3.7.0'):
        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_agent:
            raise WazuhInternalError(1600, extra_message=agent_id)
        else:
            db_agent = db_agent[0]
        conn = Connection(db_agent)
        # Find scan end time
        query = "SELECT date_last, log FROM pm_event WHERE log LIKE '% syscheck scan.'"
        conn.execute(query)

        return {'end' if log.startswith('End') else 'start': date_last for date_last, log in conn}
    else:
        fim_scan_info = my_agent._load_info_from_agent_db(table='scan_info', select={'end_scan', 'start_scan'},
                                                          filters={'module': 'fim'})[0]

        # Post-processing
        # Format timestamps as datetime
        end = None if not fim_scan_info['end_scan'] else datetime.fromtimestamp(float(fim_scan_info['end_scan']))
        start = None if not fim_scan_info['start_scan'] else datetime.fromtimestamp(float(fim_scan_info['start_scan']))

        # If start is None or the scan is running, end is None
        return {'start': start, 'end': None if start is None or start > end else end}


@matches_privileges(actions=['syscheck:get'], resources='agent:id:{agent_id}')
def files(agent_id=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
          filters={}):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :param select: Selects which fields to return.
    :param filters: Fields to filter by
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    # Pre-processing
    parameters = {"date", "mtime", "file", "size", "perm", "uname", "gname", "md5", "sha1", "sha256", "inode", "gid",
                  "uid", "type", "attributes", "symbolic_path"}
    summary_parameters = {"date", "mtime", "file"}

    if sort is not None:
        for element in sort['fields']:
            if element not in parameters:
                raise WazuhError(1403, extra_message=', '.join(set(sort['fields']) - parameters),
                                 extra_remediation="Allowed fields are: {0}".format(', '.join(parameters)))

    if select is None:
        select = summary_parameters if summary else parameters
    else:
        select = set(select)
        if not select.issubset(parameters):
            raise WazuhError(1724, extra_message=', '.join(select - parameters),
                             extra_remediation="Allowed fields are: {0}".format(', '.join(parameters)))

    if 'hash' in filters:
        or_filters = {'md5': filters['hash'], 'sha1': filters['hash'], 'sha256': filters['hash']}
        del filters['hash']
    else:
        or_filters = {}

    # Processing
    items, total_items = Agent(agent_id)._load_info_from_agent_db(table='fim_entry', select=select, offset=offset,
                                                                  limit=limit, sort=sort, search=search,
                                                                  filters=filters, count=True, or_filters=or_filters)

    # Post-processing
    # Format timestamps as datetime
    for date_field in select & {'mtime', 'date'}:
        for item in items:
            # Date fields with value 0 are returned as None
            item[date_field] = None if item[date_field] == 0 \
                                    else datetime.fromtimestamp(float(item[date_field]))

    return {'totalItems': total_items, 'items': items}
