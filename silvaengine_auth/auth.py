#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from graphene import Schema
from silvaengine_utility import Utility
from .schema import Query, Mutations, type_class
from .models import BaseModel


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
        query = params.get("query")
        if query is not None:
            result = schema.execute(query, context_value=ctx, variable_values=variables)
        mutation = params.get("mutation")
        if mutation is not None:
            result = schema.execute(
                mutation, context_value=ctx, variable_values=variables
            )

        response = {
            "data": dict(result.data) if result.data != None else None,
        }
        if result.errors != None:
            response["errors"] = [str(error) for error in result.errors]
        return Utility.json_dumps(response)