#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import traceback, uuid
from datetime import datetime
from .object_types import (
    ResourceType,
    RoleType,
    ResourceInputType,
    RoleInputType,
    PermissionType,
    PermissionInputType,
)
from .models import BaseModel, ResourceModel, RoleModel
from graphql import parse
from graphene import ObjectType, String, Int, List, Field, Schema, Mutation
from silvaengine_utility import Utility


def type_class():
    return [ResourceType, RoleType, PermissionType]


def insert_update_resource(resource_input):
    # insert == create
    # update == update
    # query == select
    # delete == delete
    # Update the resource record.
    if resource_input.resource_id and resource_input.service:
        resource = ResourceModel.get(resource_input.resource_id, resource_input.service)

        resource.update(
            actions=[
                ResourceModel.updated_at.set(datetime.utcnow()),
                ResourceModel.updated_by.set(resource_input.updated_by),
                ResourceModel.name.set(resource_input.name),
                ResourceModel.path.set(resource_input.path),
                ResourceModel.status.set(resource_input.status),
            ]
        )
        return ResourceModel.get(resource_input.resource_id, resource_input.service)

    # Insert a resource record.
    resource_id = str(uuid.uuid1())
    ResourceModel(
        resource_id,
        resource_input.service,
        **{
            "name": resource_input.name,
            "path": resource_input.path,
            "status": resource_input.status,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "updated_by": resource_input.updated_by,
        }
    ).save()

    return ResourceModel.get(resource_id, resource_input.service)


def insert_update_role(role_input):
    # Update the role record.
    if role_input.role_id:
        role = RoleModel.get(role_input.role_id)
        role.update(
            actions=[
                RoleModel.updated_at.set(datetime.utcnow()),
                RoleModel.updated_by.set(role_input.updated_by),
                RoleModel.name.set(role_input.name),
                RoleModel.permissions.set(role_input.permissions),
                RoleModel.user_ids.set(role_input.user_ids),
            ]
        )
        return RoleModel.get(role_input.role_id)

    # Insert a role record.
    role_id = str(uuid.uuid1())
    RoleModel(
        role_id,
        **{
            "name": role_input.name,
            "permissions": role_input.permissions,
            "user_ids": role_input.user_ids,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "updated_by": role_input.updated_by,
        }
    ).save()

    return RoleModel.get(role_id)


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
        limit = kwargs.get("limit")
        last_evaluated_key = kwargs.get("last_evaluated_key")
        resource_id = kwargs.get("resource_id")

        if resource_id is not None:
            resources = ResourceModel.query(resource_id, None)
            return [
                ResourceType(
                    **Utility.json_loads(
                        Utility.json_dumps(resource.__dict__["attribute_values"])
                    )
                )
                for resource in resources
            ]

        if last_evaluated_key is not None:
            results = ResourceModel.scan(
                limit=int(limit),
                last_evaluated_key=Utility.json_loads(last_evaluated_key),
            )
            resources = [resource for resource in results]
            last_evaluated_key = results.last_evaluated_key
        else:
            results = ResourceModel.scan(limit=int(limit))
            resources = [resource for resource in results]
            last_evaluated_key = results.last_evaluated_key

        return [
            ResourceType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        dict(
                            {
                                "last_evaluated_key": Utility.json_dumps(
                                    last_evaluated_key
                                )
                            },
                            **resource.__dict__["attribute_values"]
                        )
                    )
                )
            )
            for resource in resources
        ]

    def resolve_roles(self, info, **kwargs):
        limit = kwargs.get("limit")
        last_evaluated_key = kwargs.get("last_evaluated_key")
        role_id = kwargs.get("role_id")

        if role_id is not None:
            role = RolesModel.get(role_id)

            return [
                RoleType(
                    **Utility.json_loads(
                        Utility.json_dumps(role.__dict__["attribute_values"])
                    )
                )
            ]

        if last_evaluated_key is not None:
            results = RoleModel.scan(
                limit=int(limit),
                last_evaluated_key=Utility.json_loads(last_evaluated_key),
            )
            roles = [role for role in results]
            last_evaluated_key = results.last_evaluated_key
        else:
            results = RoleModel.scan(limit=int(limit))
            roles = [role for role in results]
            last_evaluated_key = results.last_evaluated_key

        return [
            RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        dict(
                            {
                                "last_evaluated_key": Utility.json_dumps(
                                    last_evaluated_key
                                )
                            },
                            **role.__dict__["attribute_values"]
                        )
                    )
                )
            )
            for role in roles
        ]


# Append or modify resource info.
class InsertUpdateResource(Mutation):
    resource = Field(ResourceType)

    class Arguments:
        resource_input = ResourceInputType(required=True)

    @staticmethod
    def mutate(root, info, resource_input=None):
        try:
            _resource = insert_update_resource(resource_input)

            resource = ResourceType(
                **Utility.json_loads(
                    Utility.json_dumps(_resource.__dict__["attribute_values"])
                )
            )
        except Exception:
            log = traceback.format_exc()
            info.context.get("logger").exception(log)
            raise

        return InsertUpdateResource(resource=resource)


# Append or modify role info.
class InsertUpdateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = insert_update_role(role_input)
            role = RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(_role.__dict__["attribute_values"])
                )
            )
        except Exception:
            log = traceback.format_exc()
            info.context.get("logger").exception(log)
            print("Exception")
            raise

        return InsertUpdateRole(role=role)


class Mutations(ObjectType):
    insert_update_resource = InsertUpdateResource.Field()
    insert_update_role = InsertUpdateRole.Field()


# Generate API documents.
def graphql_schema_doc():
    from graphdoc import to_doc

    schema = Schema(
        query=Query,
        mutation=Mutations,
        types=type_class(),
    )

    return to_doc(schema)
