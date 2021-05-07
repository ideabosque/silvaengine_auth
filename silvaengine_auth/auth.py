#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from graphene import Schema
from silvaengine_utility import Utility
from .schema import Query, Mutations, type_class
from .models import BaseModel, ResourceModel, RoleModel


class Auth(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting

        if (
            setting.get("region_name")
            and setting.get("aws_access_key_id")
            and setting.get("aws_secret_access_key")
        ):
            BaseModel.Meta.region = setting.get("region_name")
            BaseModel.Meta.aws_access_key_id = setting.get("aws_access_key_id")
            BaseModel.Meta.aws_secret_access_key = setting.get("aws_secret_access_key")

    def auth_graphql(self, **params):
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
    def isAuthorized(**kwargs):
        uid = kwargs.get("uid")
        path = kwargs.get("path")
        permission = kwargs.get("permission")

        if not uid or not path or not permission:
            return False

        # 1. Fetch resource by request path
        # TODO: Use index query to instead of the scan
        resources = [
            resource for resource in ResourceModel.scan(ResourceModel.path == path)
        ]

        if len(resources) < 1:
            return False

        resourceId = resources.pop().resource_id

        if not resourceId:
            return False

        # 2. Fetch role by user id
        roles = RoleModel.scan(RoleModel.user_ids.contains(uid))

        # 3. Check the path of request is be contained  by the permissions of role
        # 3.1 If the path has exist, compare their permission
        for role in roles:
            if len(role.permissions) > 0:
                for rule in role.permissions:
                    if (
                        rule.get("resource_id") == resourceId
                        and rule.get("permission") & permission
                    ):
                        return True

        return False
