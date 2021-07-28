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
)

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
                    "create": [{"action": "createRole", "label": "Create Role"}],
                    "update": [{"action": "updateRole", "label": "Modify Role"}],
                    "delete": [{"action": "deleteRole", "label": "Delete Role"}],
                    "query": [{"action": "roles", "label": "View Roles"}],
                    "type": "RequestResponse",
                    "support_methods": ["POST"],
                    "is_auth_required": False,
                    "is_graphql": True,
                }
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

            ctx = {"logger": self.logger, "setting": self.setting}
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

    # Authorize
    def authorize(self, event, context):
        try:
            return _authorize_response(event, context)
        except Exception as e:
            raise e

    # Authorize
    def verify_permission(self, event, context):
        try:
            return _verify_permission(event, context)
        except Exception as e:
            raise e
