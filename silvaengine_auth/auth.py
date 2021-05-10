#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from graphene import Schema
from silvaengine_utility import Utility
from .schema import Query, Mutations, type_class
from .models import BaseModel, ResourceModel, RoleModel
from .utils import extract_fields_from_ast
import json, os


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

        # query
        query = params.get("query")

        if query is not None:
            result = schema.execute(query, context_value=ctx, variable_values=variables)

        # insert / update / delete
        mutation = params.get("mutation")

        if mutation is not None:
            result = schema.execute(
                mutation, context_value=ctx, variable_values=variables
            )

        # response
        response = {
            "data": dict(result.data) if result.data != None else None,
        }

        if result.errors != None:
            response["errors"] = [str(error) for error in result.errors]

        return Utility.json_dumps(response)

    @staticmethod
    def is_authorized(event, logger):
        uid = event["requestContext"]["authorizer"]["claims"]["sub"]
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
        # create - 1, read - 2, update - 4, delete - 8
        permission = 0
        fields = extract_fields_from_ast(body, deepth=1)

        if "mutation" in fields:
            # create - 1, read - 2, update = 4, delete = 8
            for operation in event["fnConfigurations"].config.mutations:
                fn = (
                    (event["fnConfigurations"].config.mutations[operation])
                    .strip()
                    .lower()
                )

                logger.info(fn)

                if fn in fields["mutation"]:
                    if operation.lower() == "create":
                        permission += 1
                    elif operation.lower() == "update":
                        permission += 4
                    elif operation.lower() == "delete":
                        permission += 8
        elif "query" in fields:  # @TODO: Check query fields permission
            permission += 2

        logger.info(permission)

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

        # 2. Fetch role by user id
        roles = RoleModel.scan(RoleModel.user_ids.contains(uid))

        # 3. Check the path of request is be contained  by the permissions of role
        # 3.1 If the path has exist, compare their permission
        for role in roles:
            if len(role.permissions) > 0:
                for rule in role.permissions:
                    logger.info(rule.get("permission"))
                    if (
                        rule.get("resource_id") == resource_id
                        and int(rule.get("permission")) & permission
                    ):
                        return True

        return False
