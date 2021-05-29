#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

from graphene import Schema
from silvaengine_utility import Utility
from .schema import Query, Mutations, type_class
from .models import ResourceModel, RoleModel
from .utils import extract_fields_from_ast
from hashlib import md5
import json

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
        logger.info("SilvaEngine Auth isAuthorized")
        logger.info(event)

        if (
            not event.get("requestContext")
            or not event.get("pathParameters")
            or not event.get("pathParameters").get("proxy")
            or not event.get("headers")
            or not event.get("body")
            or not event.get("fnConfigurations")
            or not event.get("requestContext").get("authorizer")
            or not event.get("requestContext").get("authorizer").get("claims")
            or not event.get("requestContext")
            .get("authorizer")
            .get("claims")
            .get("sub")
        ):
            return False

        uid = event.get("requestContext").get("authorizer").get("claims").get("sub")
        role_id = (
            event.get("requestContext")
            .get("authorizer")
            .get("claims")
            .get("custom:custom:role_id")
        )
        body = event.get("body")
        function_name = event.get("pathParameters").get("proxy").strip()
        function_config = event.get("fnConfigurations")
        content_type = event.get("headers").get("Content-Type")
        area = event.get("pathParameters").get("area")
        endpoint_id = event.get("pathParameters").get("endpoint_id")
        # path = f"/{area}/{endpoint_id}/{function_name}"
        # method = event["httpMethod"]

        if content_type and content_type.strip().lower() == "application/json":
            body_json = json.loads(body)

            if "query" in body_json:
                body = body_json["query"]

        # Parse the graphql request's body to AST and extract fields from the AST
        # extract_fields_from_ast(schema, operation, deepth)
        # operation = [mutation | query]
        # create - 1, read - 2, update - 4, delete - 8 crud
        if not function_config.config.operations:
            return False

        operations = function_config.config.operations
        permission = 0
        fields = extract_fields_from_ast(body, deepth=1)

        if "mutation" in fields:
            # create - 1, query - 2, update = 4, delete = 8
            for operation in operations:
                functions = operations[operation]

                if type(functions) is not list or len(functions) < 1:
                    continue

                for fn in functions:
                    if fn.strip().lower() in fields.get("mutation"):
                        if operation.lower() == "create":
                            permission += 1
                        elif operation.lower() == "update":
                            permission += 4
                        elif operation.lower() == "delete":
                            permission += 8
        elif "query" in fields:  # @TODO: Check query fields permission
            if (
                operations.query
                and type(operations.query) is list
                and len(operations.query) > 0
            ):
                for fn in operations.query:
                    if fn.strip().lower() in fields.get("query"):
                        permission += 2
            else:
                permission += 2

        if (
            not permission
            or not function_config.config
            or not function_config.config.module_name
            or not function_config.config.class_name
        ):
            return False

        # 1. Fetch resource by request path
        # TODO: Use index query to instead of the scan
        factor = "{}-{}-{}".format(
            function_config.config.module_name.strip(),
            function_config.config.class_name.strip(),
            function_name,
        ).lower()
        resource_id = md5(factor.encode(encoding="UTF-8")).hexdigest()
        # resources = [
        #     # resource for resource in ResourceModel.scan(ResourceModel.path == path)
        #     resource
        #     for resource in ResourceModel.query(None, None, ResourceModel.path == path)
        # ]

        # if len(resources) < 1:
        #     return False

        # resource_id = resources.pop().resource_id

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

        for role in roles:
            if check_permission(role, permission):
                return True

        return False
