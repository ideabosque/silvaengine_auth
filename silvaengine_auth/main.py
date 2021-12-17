#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function


__author__ = "bl"

from graphene import Schema
from hashlib import md5
from silvaengine_utility import Utility
from .schema import (
    RoleQuery,
    RoleMutations,
    CertificateQuery,
    role_type_class,
    certificate_type_class,
)
from .handlers import (
    _verify_permission,
    _authorize_response,
    _get_roles_by_cognito_user_sub,
    _get_users_by_role_type,
    _create_relationship_handler,
    _get_roles_by_type,
    _delete_relationships_by_condition,
    _check_user_permissions,
)
from .models import RoleRelationshipType

# Hook function applied to deployment
def deploy() -> list:
    return [
        {
            "service": "permissions",
            "class": "Auth",
            "functions": {
                "role_graphql": {
                    "is_static": True,
                    "label": "Permissions",
                    "create": [
                        {
                            "action": "createRole",
                            "label": "Create Role",
                        },
                        {
                            "action": "createRelationship",
                            "label": "Create relationship",
                        },
                    ],
                    "update": [
                        {
                            "action": "updateRole",
                            "label": "Modify Role",
                        },
                        {
                            "action": "updateRelationship",
                            "label": "Update relationship",
                        },
                        {
                            "action": "saveRelationships",
                            "label": "Bulk save relationships",
                        },
                    ],
                    "delete": [
                        {
                            "action": "deleteRole",
                            "label": "Delete Role",
                        },
                        {
                            "action": "deleteRelationship",
                            "label": "Delete relationship",
                        },
                    ],
                    "query": [
                        {
                            "action": "roles",
                            "label": "View Roles",
                        },
                        {
                            "action": "role",
                            "label": "View Role",
                        },
                        {
                            "action": "users",
                            "label": "Query Permission Relationships",
                        },
                        {
                            "action": "detection",
                            "label": "Role uniqueness detection",
                        },
                    ],
                    "type": "RequestResponse",
                    "support_methods": ["POST"],
                    "is_auth_required": True,
                    "is_graphql": True,
                },
                "login_graphql": {
                    "is_static": False,
                    "label": "Login",
                    "create": [],
                    "update": [],
                    "delete": [],
                    "query": [{"action": "certificate", "label": "User Login"}],
                    "type": "RequestResponse",
                    "support_methods": ["POST"],
                    "is_auth_required": False,
                    "is_graphql": True,
                    "disabled_in_resources": True,
                },
            },
        }
    ]


class Auth(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting

    # Role interface by graphql
    def role_graphql(self, **params):
        try:
            schema = Schema(
                query=RoleQuery,
                mutation=RoleMutations,
                types=role_type_class(),
            )
            default = {"authorizer": {"is_admin": "0", "seller_id": 2018}}
            ctx = {
                "logger": self.logger,
                "setting": self.setting,
                "context": params.get("context", default),
            }
            variables = params.get("variables", {})
            query = params.get("query")

            if query is not None:
                execution_result = schema.execute(
                    query, context_value=ctx, variable_values=variables
                )

            mutation = params.get("mutation")

            if mutation is not None:
                execution_result = schema.execute(
                    mutation, context_value=ctx, variable_values=variables
                )

            if not execution_result:
                return None

            status_code = 400 if execution_result.invalid else 200

            if execution_result.errors:
                return Utility.json_dumps(
                    {
                        "errors": [
                            Utility.format_error(e) for e in execution_result.errors
                        ],
                        "status_code": 500,
                    }
                )

            return Utility.json_dumps(
                {
                    "data": execution_result.data,
                    "status_code": status_code,
                }
            )
        except Exception as e:
            raise e

    # Role interface by graphql
    def login_graphql(self, **params):
        try:
            schema = Schema(
                query=CertificateQuery,
                types=certificate_type_class(),
            )
            ctx = {"logger": self.logger, "setting": self.setting}
            variables = params.get("variables", {})
            query = params.get("query")

            if query is not None:
                execution_result = schema.execute(
                    query, context_value=ctx, variable_values=variables
                )

                if execution_result.errors:
                    raise Exception(execution_result.errors, 500)
                elif execution_result.invalid:
                    raise Exception("Request data of is invalid", 400)
                elif not execution_result.data:
                    raise Exception("No data", 406)

                return Utility.json_dumps(
                    {
                        "data": execution_result.data,
                        "status_code": 200,
                    }
                )

            raise Exception("Request body is invalid", 400)
        except Exception as e:
            raise e

    # Authorize token
    def authorize(self, event, context):
        try:
            return _authorize_response(event, context)
        except Exception as e:
            raise e

    # Authorize user permissions
    def verify_permission(self, event, context):
        try:
            return _verify_permission(event, context)
        except Exception as e:
            raise e

    # Get roles
    def get_roles_by_cognito_user_sub(
        self,
        cognito_user_sub,
        relationship_type,
        group_id=None,
        ignore_permissions=True,
    ):
        try:
            return _get_roles_by_cognito_user_sub(
                cognito_user_sub, relationship_type, group_id, ignore_permissions
            )
        except Exception as e:
            raise e

    # Get users
    def get_users_by_role_type(self, role_types, relationship_type=0, ids=None) -> list:
        try:
            return _get_users_by_role_type(role_types, relationship_type, ids)
        except Exception as e:
            raise e

    # Save role relationships
    def save_role_relationship(
        self,
        info,
        role_type,
        relationship_type,
        group_ids,
        user_ids,
        updated_by=None,
    ):
        try:
            # 1. Get roles by role type
            roles = _get_roles_by_type([role_type])

            # 2. save relationship.
            if type(roles.get(role_type)) is list and type(user_ids) is list:
                for role in roles.get(role_type):
                    kwargs = {
                        "role_ids": [role.role_id],
                        "relationship_type": relationship_type,
                        "user_ids": user_ids,
                        "group_ids": list(set(group_ids))
                        if type(group_ids) is list
                        else [str(group_ids).strip()],
                    }

                    if relationship_type == RoleRelationshipType.FACTORY.value:
                        del kwargs["group_ids"]
                    else:
                        del kwargs["user_ids"]

                    _delete_relationships_by_condition(**kwargs)

                    if len(user_ids):
                        for user_id in list(set(user_ids)):
                            kwargs = {
                                "role_id": role.role_id,
                                "relationship_type": relationship_type,
                                "user_id": user_id,
                                "updated_by": updated_by,
                                "status": True,
                            }

                            if type(group_ids) is list:
                                if len(group_ids):
                                    for group_id in list(set(group_ids)):
                                        if str(group_id).strip() != "":
                                            kwargs["group_id"] = str(group_id).strip()

                                            _create_relationship_handler(info, kwargs)
                            else:
                                kwargs["group_id"] = str(group_ids).strip()

                                _create_relationship_handler(info, kwargs)

        except Exception as e:
            raise e

    # Assign users to role.
    def assign_roles_to_users(
        self,
        info,
        role_users_map,
        relationship_type,
        updated_by,
        group_id=None,
        is_remove_existed=True,
    ):
        try:
            if type(role_users_map) is dict and len(role_users_map):
                # group_ids = None

                # if relationship_type != RoleRelationshipType.ADMINISTRATOR.value:
                if group_id:
                    group_ids = group_id if type(group_id) is list else [group_id]

                for role_id, user_ids in role_users_map.items():
                    if is_remove_existed:
                        _delete_relationships_by_condition(
                            relationship_type=relationship_type,
                            group_ids=group_ids,
                            user_ids=user_ids,
                            role_ids=role_id,
                        )

                    for user_id in user_ids:
                        kwargs = {
                            "role_id": str(role_id).strip(),
                            "relationship_type": relationship_type,
                            "user_id": user_id,
                            "updated_by": updated_by,
                            "status": True,
                        }

                        if group_ids is not None:
                            for group_id in list(set(group_ids)):
                                kwargs["group_id"] = group_id

                                _create_relationship_handler(info, kwargs)
                        else:
                            _create_relationship_handler(info, kwargs)
        except Exception as e:
            raise e

    # Remove user's role
    def remove_roles_from_users(
        self, info, relationship_type, user_ids=None, group_ids=None, role_ids=None
    ):
        try:
            _delete_relationships_by_condition(
                relationship_type=relationship_type,
                group_ids=group_ids,
                user_ids=user_ids,
                role_ids=role_ids,
            )

        except Exception as e:
            raise e

    # Check user permissions.
    def check_user_permissions(
        self,
        module_name,
        class_name,
        function_name,
        operation_type,
        operation,
        relationship_type,
        user_id,
        group_id,
    ):
        try:
            return _check_user_permissions(
                module_name=module_name,
                class_name=class_name,
                function_name=function_name,
                operation_type=operation_type,
                operation=operation,
                relationship_type=relationship_type,
                user_id=user_id,
                group_id=group_id,
            )

        except Exception as e:
            raise e

    # Get roles
    def get_roles_by_specific_user(
        self,
        user_id,
        relationship_type,
        group_id=None,
        ignore_permissions=True,
    ):
        try:
            roles = _get_roles_by_cognito_user_sub(
                user_id, relationship_type, group_id, ignore_permissions
            )

            if len(roles):
                return roles

            return None
        except Exception as e:
            raise e
