# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import logging
import re

import connexion

from api.authentication import generate_token
from api.models.token_response import TokenResponse  # noqa: E501
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.user_manager import Users
from ..util import remove_nones_to_dict, exception_handler, raise_if_exc

logger = logging.getLogger('wazuh')
loop = asyncio.get_event_loop()
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)



def login_user(user, auth_context=None):  # noqa: E501
    """User/password authentication to get an access token

    This method should be called to get an API token. This token will expire at some time. # noqa: E501


    :rtype: TokenResponse
    """
    auth_context_new = {
        'user': user
    }

    # if auth_context is None:
    #     auth_context = {
    #         "disabled": False,
    #         "name": "Bill",
    #         "office": "20",
    #         "department": [
    #             "Technical"
    #         ],
    #         "bindings": {
    #             "authLevel": [
    #                 "basic", "advanced-agents", "administrator"
    #             ],
    #             "area": [
    #                 "agents", "syscheck", "syscollector"
    #             ]
    #         },
    #         "test": {
    #             "new": {
    #                 "test2": ["new"]
    #             },
    #             "test": "new2"
    #         }
    #     }
    auth_context = json.dumps(auth_context_new)

    return TokenResponse(token=generate_token(user, auth_context)), 200

@exception_handler
def get_users(wait_for_complete= None, pretty= None):
    """
    Get username of a specified user
    :param user_id: Username of an user
    """

    dapi = DistributedAPI(f=Users.get_users,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200

@exception_handler
def get_user(username= None, wait_for_complete= None, pretty= None):
    """
    Get username of a specified user
    :param user_id: Username of an user
    """
    f_kwargs = {'username': username}

    dapi = DistributedAPI(f=Users.get_user_id,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200

@exception_handler
def create_user(wait_for_complete= None, pretty= None):
    """
    Create a new user in all nodes.
    This method will create a user in the master node and propagate it to all available workers.
    """
    f_kwargs = {**{}, **connexion.request.get_json()}

    dapi = DistributedAPI(f=Users.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200

@exception_handler
def update_user(username= None, wait_for_complete= None, pretty= None):
    """
    Modify an existent user in all nodes.
    This method will modify the password of an user in the master node and propagate it to all available workers.
    """
    f_kwargs = {'username': username, **{}, **connexion.request.get_json()}

    dapi = DistributedAPI(f=Users.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200

@exception_handler
def delete_user(username= None, wait_for_complete= None, pretty= None):
    """
    Delete an existent user in all nodes.
    This method will modify the password of an user in the master node and propagate it to all available workers.
    """
    f_kwargs = {'username': username}

    dapi = DistributedAPI(f=Users.delete_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200
