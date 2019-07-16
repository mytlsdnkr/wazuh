

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.agent import Agent
from wazuh.ossec_queue import OssecQueue
from wazuh.wdb import WazuhDBConnection


def restart_local():
    """
    Runs syscheck/rootcheck in agent 000 (local)

    :return: Message.
    """
    SYSCHECK_RESTART = "{0}/var/run/.syscheck_run".format(common.ossec_path)
    fp = open(SYSCHECK_RESTART, 'w')
    fp.write('{0}\n'.format(SYSCHECK_RESTART))
    fp.close()

    return "Restarting Syscheck/Rootcheck locally"


def restart(agent_id=None):
    """
    Runs syscheck/rootcheck in agent_id or all agents

    :param agent_id: Agent ID (All agents if agent_id is None)
    :return: Message.
    """
    oq = OssecQueue(common.ARQUEUE)
    result = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART, agent_id)
    oq.close()

    return result


def clear(agent_id):
    """
    Clears the syscheck database of an agent.

    :param agent_id: Agent ID.
    :return: Message.
    """
    # Check if the agent exists
    Agent(agent_id).get_basic_information()

    wdb_conn = WazuhDBConnection()
    wdb_conn.execute("agent {} sql delete from fim_entry".format(agent_id), delete=True)
    # Update key fields which contains keys to value 000
    wdb_conn.execute("agent {} sql update metadata set value = '000' where key like 'fim_db%'"
                     .format(agent_id), update=True)
    wdb_conn.execute("agent {} sql update metadata set value = '000' where key = 'syscheck-db-completed'"
                     .format(agent_id), update=True)

    return "Syscheck database deleted"
