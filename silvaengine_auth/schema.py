#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import traceback, uuid
from datetime import datetime
from .object_types import PermissionType, RoleType, PermissionInputType, RoleInputType
from .models import BaseModel, PermissionsModel, RolesModel
from graphene import ObjectType, String, Int, List, Field, Schema, Mutation
from silvaengine_utility import Utility


def type_class():
    return [PermissionType, RoleType]


def insert_update_permission(permission_input):
    # Update the permission record.
    if permission_input.permission_id and permission_input.service:
        permission = PermissionsModel.get(
            permission_input.permission_id, permission_input.service
        )

        permission.update(
            actions=[
                PermissionsModel.updated_at.set(datetime.utcnow()),
                PermissionsModel.updated_by.set(permission_input.updated_by),
                PermissionsModel.action.set(permission_input.action),
                PermissionsModel.paths.set(permission_input.paths),
            ]
        )
        return PermissionsModel.get(
            permission_input.permission_id, permission_input.service
        )

    # Insert a permission record.
    permission_id = str(uuid.uuid1())
    PermissionsModel(
        permission_id,
        permission_input.service,
        **{
            "action": permission_input.action,
            "paths": permission_input.paths,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "updated_by": permission_input.updated_by,
        }
    ).save()

    return PermissionsModel.get(permission_id, permission_input.service)


def insert_update_role(role_input):
    # Update the role record.
    if role_input.role_id:
        role = RolesModel.get(role_input.role_id)
        role.update(
            actions=[
                RolesModel.updated_at.set(datetime.utcnow()),
                RolesModel.updated_by.set(role_input.updated_by),
                RolesModel.name.set(role_input.name),
                RolesModel.permission_ids.set(role_input.permission_ids),
                RolesModel.user_ids.set(role_input.user_ids),
            ]
        )
        return RolesModel.get(role_input.role_id)

    # Insert a role record.
    role_id = str(uuid.uuid1())
    RolesModel(
        role_id,
        **{
            "name": role_input.name,
            "permission_ids": role_input.permission_ids,
            "user_ids": role_input.user_ids,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "updated_by": role_input.updated_by,
        }
    ).save()

    return RolesModel.get(role_id)


class Query(ObjectType):
    permissions = List(
        PermissionType,
        limit=Int(),
        last_evaluated_key=String(),
        permission_id=String(),
    )

    roles = List(
        RoleType,
        limit=Int(),
        last_evaluated_key=String(),
        role_id=String(),
    )

    def resolve_permissions(self, info, **kwargs):
        limit = kwargs.get("limit")
        last_evaluated_key = kwargs.get("last_evaluated_key")
        permission_id = kwargs.get("permission_id")
        if permission_id is not None:
            permissions = PermissionsModel.query(permission_id, None)
            return [
                PermissionType(
                    **Utility.json_loads(
                        Utility.json_dumps(permission.__dict__["attribute_values"])
                    )
                )
                for permission in permissions
            ]

        if last_evaluated_key is not None:
            results = PermissionsModel.scan(
                limit=int(limit),
                last_evaluated_key=Utility.json_loads(last_evaluated_key),
            )
            permissions = [permission for permission in results]
            last_evaluated_key = results.last_evaluated_key
        else:
            results = PermissionsModel.scan(limit=int(limit))
            permissions = [permission for permission in results]
            last_evaluated_key = results.last_evaluated_key
        return [
            PermissionType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        dict(
                            {
                                "last_evaluated_key": Utility.json_dumps(
                                    last_evaluated_key
                                )
                            },
                            **permission.__dict__["attribute_values"]
                        )
                    )
                )
            )
            for permission in permissions
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
            results = RolesModel.scan(
                limit=int(limit),
                last_evaluated_key=Utility.json_loads(last_evaluated_key),
            )
            roles = [role for role in results]
            last_evaluated_key = results.last_evaluated_key
        else:
            results = RolesModel.scan(limit=int(limit))
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


class InsertUpdatePermission(Mutation):
    permission = Field(PermissionType)

    class Arguments:
        permission_input = PermissionInputType(required=True)

    @staticmethod
    def mutate(root, info, permission_input=None):
        try:
            _permission = insert_update_permission(permission_input)

            permission = PermissionType(
                **Utility.json_loads(
                    Utility.json_dumps(_permission.__dict__["attribute_values"])
                )
            )
        except Exception:
            log = traceback.format_exc()
            info.context.get("logger").exception(log)
            raise

        return InsertUpdatePermission(permission=permission)


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
            raise

        return InsertUpdateRole(role=role)


class Mutations(ObjectType):
    insert_update_permission = InsertUpdatePermission.Field()
    insert_update_role = InsertUpdateRole.Field()


def graphql_schema_doc():
    from graphdoc import to_doc

    schema = Schema(
        query=Query,
        mutation=Mutations,
        types=type_class(),
    )
    return to_doc(schema)