#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

from graphene import ObjectType, String, Int, Schema, Field
from .types import RolesType, PageInputType
from .queries import resolve_roles
from .mutations import CreateRole, UpdateRole, DeleteRole


def type_class():
    return [RolesType]


# Query resource or role list
class Query(ObjectType):
    roles = Field(
        RolesType,
        limit=Int(),
        last_evaluated_key=PageInputType(),
        role_id=String(),
    )

    def resolve_roles(self, info, **kwargs):
        return resolve_roles(info, **kwargs)


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
