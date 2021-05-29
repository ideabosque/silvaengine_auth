#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

from graphene import Schema
from silvaengine_utility import Utility
from .schema import Query, Mutations, type_class
from .models import ResourceModel, RoleModel
from .utils import extract_fields_from_ast
import json, os

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
                    "create": ["createRole"],
                    "update": ["updateRole"],
                    "delete": ["deleteRole"],
                    "query": ["resources", "roles"],
                    "type": "RequestResponse",
                    "support_methods": ["POST"],
                    "is_auth_required": True,
                    "is_graphql": True,
                }
            },
        }
    ]


class Auth(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting

        # if (
        #     setting.get("region_name")
        #     and setting.get("aws_access_key_id")
        #     and setting.get("aws_secret_access_key")
        # ):
        #     BaseModel.Meta.region = setting.get("region_name")
        #     BaseModel.Meta.aws_access_key_id = setting.get("aws_access_key_id")
        #     BaseModel.Meta.aws_secret_access_key = setting.get("aws_secret_access_key")

    def role_graphql(self, **params):
        schema = Schema(
            query=Query,
            mutation=Mutations,
            types=type_class(),
        )

        ctx = {"logger": self.logger}
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
                    "status_code": status_code,
                }
            )

        return Utility.json_dumps(
            {
                "data": execution_result.data,
                "status_code": status_code,
            }
        )

    @staticmethod
    def is_authorized(event, logger):
        uid = event["requestContext"]["authorizer"]["claims"]["sub"]
        role_id = event["requestContext"]["authorizer"]["claims"][
            "custom:custom:role_id"
        ]
        area = event["pathParameters"]["area"]
        content_type = event["headers"]["Content-Type"]
        endpoint_id = event["pathParameters"]["endpoint_id"]
        funct = event["pathParameters"]["proxy"]
        path = f"/{area}/{endpoint_id}/{funct}"
        body = event["body"]
        # method = event["httpMethod"]

        logger.info("SilvaEngine Auth isAuthorized")
        logger.info(event)

        if content_type.strip().lower() == "application/json":
            body_json = json.loads(body)

            if "query" in body_json:
                body = body_json["query"]

        # Parse the graphql request's body to AST and extract fields from the AST
        # extract_fields_from_ast(schema, operation, deepth)
        # operation = [mutation | query]
        # create - 1, read - 2, update - 4, delete - 8 crud
        permission = 0
        fields = extract_fields_from_ast(body, deepth=1)
        # {"mutation": ["createRole", "udpateRole", ....]}

        if "mutation" in fields:
            # create - 1, read - 2, update = 4, delete = 8
            for operation in event["fnConfigurations"].config.mutations:
                fn = (
                    (event["fnConfigurations"].config.mutations[operation])
                    .strip()
                    .lower()
                )

                if fn in fields["mutation"]:
                    if operation.lower() == "create":
                        permission += 1
                    elif operation.lower() == "update":
                        permission += 4
                    elif operation.lower() == "delete":
                        permission += 8
        elif "query" in fields:  # @TODO: Check query fields permission
            permission += 2

        if not uid or not path or not permission:
            return False

        # 1. Fetch resource by request path
        # TODO: Use index query to instead of the scan
        resources = [
            resource for resource in ResourceModel.scan(ResourceModel.path == path)
        ]

        if len(resources) < 1:
            return False

        resource_id = resources.pop().resource_id

        if not resource_id:
            return False

        # Check the path of request is be contained  by the permissions of role
        # If the path has exist, compare their permission
        def check_permission(role, permission) -> bool:
            if role and len(role.permissions) > 0:
                for rule in role.permissions:
                    if (
                        rule.get("resource_id") == resource_id
                        and int(rule.get("permission")) & permission
                    ):
                        return True
            return False

        # If user has role id, use the role id to findout their permission
        if role_id:
            role = RoleModel().get(role_id)

            return check_permission(role, permission)

        # If user has not role id, then use the user id to find their role & traverse their role permission to calculate the permission
        roles = RoleModel.scan(RoleModel.user_ids.contains(uid))
        role = RoleModel().get(role_id)

        for role in roles:
            if check_permission(role, permission):
                return True

        return False
