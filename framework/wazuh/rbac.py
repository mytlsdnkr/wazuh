# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
from functools import wraps
from glob import glob

from wazuh import common
from wazuh.RBAC import RBAC
from wazuh.database import Connection
from wazuh.exception import WazuhError, WazuhInternalError
from wazuh.utils import cut_array, sort_array, search_array


def get_groups_resources(agent_id):
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)

    conn = Connection(db_global[0])
    if agent_id == '*':
        conn.execute("SELECT name FROM `group` WHERE id IN (SELECT DISTINCT id_group FROM belongs)")
    else:
        conn.execute("SELECT name FROM `group` WHERE id IN (SELECT id_group FROM belongs WHERE id_agent = :agent_id)",
                     {'agent_id': int(agent_id)})
    result = conn.fetch_all()
    groups = ['agent:group:*']
    for group in result:
        groups.append('{0}:{1}'.format('agent:group', group[0]))

    return groups


def get_required_permissions(actions: list = None, resources: str = None, **kwargs):

    # We expose required resources for the request
    m = re.search(r'^(\w+\:\w+:)(\w+|\*|{(\w+)})$', resources)
    res_list = list()
    res_base = m.group(1)
    # If we find a '{' in the regex we obtain the dynamic resource/s
    if '{' in m.group(2):
        try:
            # Dynamic resources ids are found within the {}
            params = kwargs[m.group(3)]
            # We check if params is a list of resources or a single one in a string
            if isinstance(params, list):
                for param in params:
                    res_list.append("{0}{1}".format(res_base, param))
            else:
                res_list.append("{0}{1}".format(res_base, params))
        # KeyError occurs if required dynamic resources can't be found within request parameters
        except KeyError as e:
            raise WazuhInternalError(4001, extra_message=str(e))
    # If we don't find a regex match we obtain the static resource/s
    else:
        res_list.append(resources)

    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = res_list

    return req_permissions


def match_permissions(req_permissions: dict = None, rbac: list = None):
    mode = rbac[0]
    user_permissions = rbac[1]
    # We run through all required permissions for the request
    for req_action, req_resources in req_permissions.items():
        for req_resource in req_resources:
            # allow_match is used to keep track when a required permission is matched by a policy with an allowed effect
            allow_match = False
            # We run through the user permissions to find a match with the required permissions
            for policy in user_permissions:
                # We find if action matches
                action_match = req_action in policy['actions']
                if action_match:
                    # We find resource name to add * if not already there
                    m = re.search(r'^(\w+\:\w+:)([\w\-\.]+|\*)$', req_resource)
                    res_match = False
                    # We find if resource matches
                    if m.group(1) == 'agent:id:':
                        reqs = [req_resource]
                        reqs.extend(get_groups_resources(m.group(2)))
                        for req in reqs:
                            res_match = res_match or (req in policy['resources'])
                    elif m.group(2) != '*':
                        req_asterisk = '{0}{1}'.format(m.group(1), '*')
                        res_match = (req_resource in policy['resources']) or (req_asterisk in policy['resources'])
                    else:
                        res_match = req_resource in policy['resources']
                    # When any policy with a deny effect matches, we deny the request directly
                    if res_match and policy['effect'] == "deny":
                        return False
                    # When any policy with an allow effect matches, we set a match in allow_match and
                    # break out to continue with required permissions
                    elif res_match and policy['effect'] == "allow":
                        allow_match = True
                        break
            # If we are using white list mode and no match is found for the required permission we deny the request.
            if not allow_match and not mode:
                return False
    # If we don't find a deny match or we find an allow match for all policies in white list mode we allow the request
    return True


def matches_privileges(actions: list = None, resources: str = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            req_permissions = get_required_permissions(actions=actions, resources=resources, **kwargs)
            allow = match_permissions(req_permissions=req_permissions, rbac=kwargs['rbac'])
            if allow:
                del kwargs['rbac']
                return func(*args, **kwargs)
            else:
                raise WazuhError(4000)
        return wrapper
    return decorator



class Role:
    """
    Role Object.
    """

    SORT_FIELDS = ['name']

    def __init__(self):
        self.id = None
        self.name = None
        self.rule = None
        self.policies = list()

    def __init__(self, id, name, rule, policies=None):
        self.id = id
        self.name = name
        self.rule = rule
        self.policies = policies

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Role):
            return self.id < other.id
        else:
            raise WazuhInternalError(1204)

    def __le__(self, other):
        if isinstance(other, Role):
            return self.id <= other.id
        else:
            raise WazuhInternalError(1204)

    def __gt__(self, other):
        if isinstance(other, Role):
            return self.id > other.id
        else:
            raise WazuhInternalError(1204)

    def __ge__(self, other):
        if isinstance(other, Role):
            return self.id >= other.id
        else:
            raise WazuhInternalError(1204)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'rule': self.rule, 'policies': self.policies}

    def add_policy(self, policy):
        """
        Adds a policy to the policies list.
        :param policy: Policy to add (string or list)
        """

        Role.__add_unique_element(self.policies, policy)

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
    def get_role(role_id):
        """
        Here we will be able to obtain a certain role.

        :param role_id: Return the information of a role
        :return: Message.
        """

        return_role = None

        with RBAC.RolesManager() as rm:
            role = rm.get_role_id(id=role_id)
            if role is not None:
                return_role = role.to_dict()
                return_role['rule'] = json.loads(return_role['rule'])
                for index, policy in enumerate(return_role['policies']):
                    return_role['policies'][index]['policy'] = \
                        json.loads(return_role['policies'][index]['policy'])

        if return_role is None:
            raise WazuhError(4002)

        return return_role


    @staticmethod
    def get_roles(offset=0, limit=common.database_limit, search=None, sort=None):
        """
        Here we will be able to obtain all roles

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Message.
        """

        return_roles = list()

        with RBAC.RolesManager() as rm:
            roles = rm.get_roles()
            for role in roles:
                dict_role = role.to_dict()
                dict_role.pop('policies', None)
                dict_role['rule'] = json.loads(dict_role['rule'])
                return_roles.append(dict_role)

        if search:
            return_roles = search_array(return_roles, search['value'], search['negation'])

        if sort:
            return_roles = sort_array(return_roles, sort['fields'], sort['order'])
        else:
            return_roles = sort_array(return_roles, ['id'], 'asc')

        return {'items': cut_array(return_roles, offset, limit), 'totalItems': len(return_roles)}

    @staticmethod
    def remove_role(role_id):
        """
        Here we will be able to delete a role

        :param role_id: Role to be deleted
        :return: Message.
        """

        response = dict()

        with RBAC.RolesManager() as rm:
            if rm.delete_role(role_id):
                response['removed_roles'] = [int(role_id)]
            else:
                response['incorrect_roles'] = [int(role_id)]

        return response

    @staticmethod
    def remove_roles(list_roles):
        """
        Here we will be able to delete all roles

        :param list_roles: List of roles to be deleted
        :return: Message.
        """

        status_correct = list()
        response = dict()

        with RBAC.RolesManager() as rm:
            if len(list_roles) > 0:
                for role in list_roles:
                    if rm.delete_role(role):
                        status_correct.append(int(role))
                response['removed_roles'] = status_correct
                response['incorrect_roles'] = list(set(list_roles) ^ set(status_correct))
            else:
                response['removed_roles'] = rm.delete_all_roles()

        return response

    @staticmethod
    def add_role(name=None, rule=None):
        """
        Here we will be able to add a new role

        :param name: The new role name
        :param rule: The new rule
        :return: Message.
        """

        with RBAC.RolesManager() as rm:
            status = rm.add_role(name=name, rule=rule)
            if not status:
                raise WazuhError(4005)
            if status == -1:
                raise WazuhError(4003)

        return Role.get_role(role_id=rm.get_role(name=name).id)

    @staticmethod
    def update_role(role_id, name=None, rule=None):
        """
        Here we will be able to update a specified role

        :param role_id: Role id to be update
        :param name: The new role name
        :param rule: The new rule
        :return: Message.
        """

        if name is None and rule is None:
            raise WazuhError(4001)

        with RBAC.RolesManager() as rm:
            status = rm.update_role(role_id=role_id, name=name, rule=rule)
            if not status:
                raise WazuhError(4002)
            if status == -1:
                raise WazuhError(4003)

        return Role.get_role(role_id=role_id)


class Policy:
    """
    Policy Object.
    """

    SORT_FIELDS = ['name']

    def __init__(self):
        self.id = None
        self.name = None
        self.policy = None
        self.roles = list()

    def __init__(self, id, name, policy, roles=None):
        self.id = id
        self.name = name
        self.policy = policy
        self.roles = roles

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Policy):
            return self.id < other.id
        else:
            raise WazuhInternalError(1204)

    def __le__(self, other):
        if isinstance(other, Policy):
            return self.id <= other.id
        else:
            raise WazuhInternalError(1204)

    def __gt__(self, other):
        if isinstance(other, Policy):
            return self.id > other.id
        else:
            raise WazuhInternalError(1204)

    def __ge__(self, other):
        if isinstance(other, Policy):
            return self.id >= other.id
        else:
            raise WazuhInternalError(1204)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'policy': self.policy, 'roles': self.roles}

    def add_role(self, role):
        """
        Adds a role to the roles list.
        :param role: Role to add (string or list)
        """

        Role.__add_unique_element(self.roles, role)

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
    def get_policy(policy_id):
        """
        Here we will be able to obtain a certain policy

        :param policy_id: Return the information of a role
        :return: Message.
        """

        return_policy = None

        with RBAC.PoliciesManager() as pm:
            policy = pm.get_policy_by_id(id=policy_id)
            if policy is not None:
                return_policy = policy.to_dict()
                return_policy['policy'] = json.loads(return_policy['policy'])
                for index, role in enumerate(return_policy['roles']):
                    return_policy['roles'][index]['rule'] = \
                        json.loads(return_policy['roles'][index]['rule'])

        if return_policy is None:
            raise WazuhError(4007)

        # return {'items': return_policies, 'totalItems': len(return_policies)}
        return return_policy

    @staticmethod
    def get_policies(offset=0, limit=common.database_limit, search=None, sort=None):
        """
        Here we will be able to obtain all policies

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Message.
        """

        return_policies = list()

        with RBAC.PoliciesManager() as pm:
            policies = pm.get_policies()
            for policy in policies:
                dict_policy = policy.to_dict()
                dict_policy.pop('roles', None)
                dict_policy['policy'] = json.loads(dict_policy['policy'])
                return_policies.append(dict_policy)

        if search:
            return_policies = search_array(return_policies, search['value'], search['negation'])

        if sort:
            return_policies = sort_array(return_policies, sort['fields'], sort['order'])
        else:
            return_policies = sort_array(return_policies, ['id'], 'asc')

        return {'items': cut_array(return_policies, offset, limit), 'totalItems': len(return_policies)}

    @staticmethod
    def remove_policy(policy_id):
        """
        Here we will be able to delete a policy

        :param policy_id: Policy to be deleted
        :return: Message.
        """

        response = dict()

        with RBAC.PoliciesManager() as pm:
            if pm.delete_policy(policy_id):
                response['removed_policies'] = [int(policy_id)]
            else:
                response['incorrect_policies'] = [int(policy_id)]

        return response

    @staticmethod
    def remove_policies(list_policies):
        """
        Here we will be able to delete all policies

        :param list_policies: List of policies to be deleted
        :return: Message.
        """

        status_correct = list()
        response = dict()

        with RBAC.PoliciesManager() as pm:
            if len(list_policies) > 0:
                for policy in list_policies:
                    if pm.delete_policy(policy):
                        status_correct.append(int(policy))
                response['removed_policies'] = status_correct
                response['incorrect_policies'] = list(set(list_policies) ^ set(status_correct))
            else:
                response['removed_policies'] = pm.delete_all_policies()

        return response

    @staticmethod
    def add_policy(name=None, policy=None):
        """
        Here we will be able to add a new policy

        :param name: The new policy name
        :param policy: The new policy
        :return: Message.
        """

        with RBAC.PoliciesManager() as pm:
            status = pm.add_policy(name=name, policy=policy)
            if not status:
                raise WazuhError(4009)
            if status == -1:
                raise WazuhError(4006)
            if status == -2:
                raise WazuhError(4012)

        return Policy.get_policy(policy_id=pm.get_policy(name=name).id)

    @staticmethod
    def update_policy(policy_id, name=None, policy=None):
        """
        Here we will be able to update a specified policy

        :param policy_id: Policy id to be update
        :param name: The new policy name
        :param policy: The new policy
        :return: Message.
        """

        if name is None and policy is None:
            raise WazuhError(4001)

        with RBAC.PoliciesManager() as pm:
            status = pm.update_policy(policy_id=policy_id, name=name, policy=policy)
            if not status:
                raise WazuhError(4007)
            if status == -1:
                raise WazuhError(4006)
            if status == -2:
                raise WazuhError(4013)

        return Policy.get_policy(policy_id=policy_id)


class RolePolicy:
    """
    RolePolicy Object.
    """

    SORT_FIELDS = ['name']

    def __init__(self):
        self.role_id = None
        self.policy_id = None

    def __init__(self, role_id, policy_id):
        self.role_id = role_id
        self.policy_id = policy_id

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, RolePolicy):
            return self.id < other.id
        else:
            raise WazuhInternalError(1204)

    def __le__(self, other):
        if isinstance(other, RolePolicy):
            return self.id <= other.id
        else:
            raise WazuhInternalError(1204)

    def __gt__(self, other):
        if isinstance(other, RolePolicy):
            return self.id > other.id
        else:
            raise WazuhInternalError(1204)

    def __ge__(self, other):
        if isinstance(other, RolePolicy):
            return self.id >= other.id
        else:
            raise WazuhInternalError(1204)

    def to_dict(self):
        return {'role_id': self.roleid, 'policy_id': self.policy_id}

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
    def set_role_policy(role_id, policies_ids):
        """
        Here we will be able to add a new role-policy relation

        :param role_id: The new role_id
        :param policies_ids: List of policies ids
        :return: Message.
        """

        with RBAC.PoliciesManager() as pm:
            for policy_id in policies_ids:
                if not pm.get_policy_by_id(policy_id):
                    raise WazuhError(4007, extra_message=str(policy_id))

        with RBAC.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                role_policy = rpm.exist_role_policy(role_id, policy_id)
                if role_policy:
                    raise WazuhError(4011, extra_message='Role id '+str(role_id)+' - '+'Policy id '+str(policy_id))
                elif role_policy == -1:
                    raise WazuhError(4002, extra_message='Role id '+str(role_id))

        with RBAC.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                status = rpm.add_policy_to_role(role_id=role_id, policy_id=policy_id)
                if not status:
                    raise WazuhError(4008)
                if status == -1:
                    raise WazuhError(4002)
                if status == -2:
                    raise WazuhError(4007)

        return Role.get_role(role_id=role_id)

    @staticmethod
    def remove_role_policy(role_id, policies_ids):
        """
        Here we will be able to remove a role-policy relation

        :param role_id: The new role_id
        :param policies_ids: List of policies ids
        :return: Message.
        """

        with RBAC.PoliciesManager() as pm:
            for policy_id in policies_ids:
                if not pm.get_policy_by_id(policy_id):
                    raise WazuhError(4007, extra_message=str(policy_id))

        with RBAC.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                role_policy = rpm.exist_role_policy(role_id, policy_id)
                if not role_policy:
                    raise WazuhError(4010, extra_message='Role id '+str(role_id)+' - '+'Policy id '+str(policy_id))
                elif role_policy == -1:
                    raise WazuhError(4002, extra_message='Role id '+str(role_id))

        with RBAC.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                status = rpm.remove_policy_in_role(role_id=role_id, policy_id=policy_id)
                if not status:
                    raise WazuhError(4008)

        return Role.get_role(role_id=role_id)
