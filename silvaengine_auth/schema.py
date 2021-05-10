#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import traceback, uuid
from datetime import datetime
from graphene import ObjectType, String, Int, List, Field, Schema, Mutation
from silvaengine_utility import Utility
from .types import (
    ResourceType,
    RoleType,
)
from .models import BaseModel, ResourceModel, RoleModel
from .queries import resolve_resources, resolve_roles
from .mutations import CreateRole, UpdateRole, DeleteRole


def type_class():
    return [ResourceType, RoleType]


# Query resource or role list
class Query(ObjectType):
    resources = List(
        ResourceType,
        limit=Int(),
        last_evaluated_key=String(),
        resource_id=String(),
    )

    roles = List(
        RoleType,
        limit=Int(),
        last_evaluated_key=String(),
        role_id=String(),
    )

    def resolve_resources(self, info, **kwargs):
        return resolve_resources(info, **kwargs)

    def resolve_roles(self, info, **kwargs):
        return resolve_roles(info, **kwargs)


# Append or modify resource info.
# class InsertUpdateResource(Mutation):
#     resource = Field(ResourceType)

#     class Arguments:
#         resource_input = ResourceInputType(required=True)

#     @staticmethod
#     def mutate(root, info, resource_input=None):
#         try:
#             _resource = insert_update_resource(resource_input)

#             resource = ResourceType(
#                 **Utility.json_loads(
#                     Utility.json_dumps(_resource.__dict__["attribute_values"])
#                 )
#             )
#         except Exception:
#             log = traceback.format_exc()
#             info.context.get("logger").exception(log)
#             raise

#         return InsertUpdateResource(resource=resource)


class Mutations(ObjectType):
    # insert_update_resource = InsertUpdateResource.Field()
    create_role = CreateRole.Field()
    update_role = UpdateRole.Field()
    delete_role = DeleteRole.Field()


# Generate API documents.
def graphql_schema_doc():
    from graphdoc import to_doc

    schema = Schema(
        query=Query,
        mutation=Mutations,
        types=type_class(),
    )

    return to_doc(schema)
