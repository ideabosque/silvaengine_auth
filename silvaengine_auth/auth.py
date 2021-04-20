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


class Auth(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting
        if (
            "region_name" in setting.keys()
            and "aws_access_key_id" in setting.keys()
            and "aws_secret_access_key" in setting.keys()
        ):
            BaseModel.Meta.region = setting.get("region_name")
            BaseModel.Meta.aws_access_key_id = setting.get("aws_access_key_id")
            BaseModel.Meta.aws_secret_access_key = setting.get("aws_secret_access_key")

    def insert_update_permission(self, permission_input):
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

        # Insert the permission record.
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

    def auth_graphql(self, **params):
        outer = self

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
                                Utility.json_dumps(
                                    permission.__dict__["attribute_values"]
                                )
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
                    roles = RolesModel.query(role_id)
                    return [
                        RoleType(
                            **Utility.json_loads(
                                Utility.json_dumps(**role.__dict__["attribute_values"])
                            )
                        )
                        for role in roles
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

        ## Mutation ##

        class InsertUpdatePermission(Mutation):
            class Arguments:
                permission_input = PermissionInputType(required=True)

            permission = Field(PermissionType)

            @staticmethod
            def mutate(root, info, permission_input=None):
                try:
                    _permission = outer.insert_update_permission(permission_input)

                    permission = PermissionType(
                        **Utility.json_loads(
                            Utility.json_dumps(_permission.__dict__["attribute_values"])
                        )
                    )
                except Exception:
                    log = traceback.format_exc()
                    self.logger.exception(log)
                    raise

                return InsertUpdatePermission(permission=permission)

        class Mutations(ObjectType):
            insert_update_permission = InsertUpdatePermission.Field()

        ## Mutation ##

        schema = Schema(
            query=Query,
            mutation=Mutations,
            types=[PermissionType, RoleType],
        )

        variables = params.get("variables", {})
        query = params.get("query")
        if query is not None:
            result = schema.execute(query, variables=variables)
        mutation = params.get("mutation")
        if mutation is not None:
            result = schema.execute(mutation, variables=variables)

        response = {
            "data": dict(result.data) if result.data != None else None,
        }
        if result.errors != None:
            response["errors"] = [str(error) for error in result.errors]
        return Utility.json_dumps(response)


if __name__ == "__main__":
    import logging, sys

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logger = logging.getLogger()
    setting = {
        "region_name": "us-west-2",  # The AWS region.
        "aws_access_key_id": "AKIAUOKFFIAWI5WMZOIA",  # AWS ACCESS KEY ID.
        "aws_secret_access_key": "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",  # AWS SECRET ACCESS KEY.
    }

    auth = Auth(logger, **setting)

    # mutation = """
    #     mutation insertUpdatePermission(
    #             $permissionId: String!,
    #             $service: String!,
    #             $action: String!,
    #             $paths: [String]!,
    #             $updatedBy: String!
    #         ) {
    #         insertUpdatePermission(
    #             permissionInput:{
    #                 permissionId: $permissionId,
    #                 service: $service,
    #                 action: $action,
    #                 paths: $paths,
    #                 updatedBy: $updatedBy
    #             }
    #         ) {
    #             permission{
    #                 permissionId
    #                 service
    #                 action
    #                 paths
    #                 createdAt
    #                 updatedAt
    #                 updatedBy
    #             }
    #         }
    #     }
    # """

    # variables = {
    #     "permissionId": "666c6f90-a013-11eb-8016-0242ac120002",
    #     "service": "xyz",
    #     "action": "read",
    #     "paths": ["abc", "edf"],
    #     "updatedBy": "99999",
    # }

    # payload = {"mutation": mutation, "variables": variables}

    # query = """
    #     query getPermissions(
    #             $limit: Int!
    #         ){
    #         permissions(
    #             limit: $limit
    #         ){
    #             permissionId
    #             service
    #             action
    #             paths
    #             createdAt
    #             updatedAt
    #             updatedBy
    #             lastEvaluatedKey
    #         }
    #     }
    # """

    # variables = {"limit": 1}

    query = """
        query getPermissions(
                $limit: Int!,
                $lastEvaluatedKey: String!
            ){
            permissions(
                limit: $limit,
                lastEvaluatedKey: $lastEvaluatedKey
            ){
                permissionId
                service
                action
                paths
                createdAt
                updatedAt
                updatedBy
                lastEvaluatedKey
            }
        }
    """

    variables = {
        "limit": 1,
        "lastEvaluatedKey": """{\n    \"service\": {\n        \"S\": \"xyz\"\n    },\n    \"permission_id\": {\n        \"S\": \"666c6f90-a013-11eb-8016-0242ac120002\"\n    }\n}""",
    }

    # query = """
    #     query getPermissions(
    #             $permissionId: String!
    #         ){
    #         permissions(
    #             permissionId: $permissionId
    #         ){
    #             permissionId
    #             service
    #             action
    #             paths
    #             createdAt
    #             updatedAt
    #             updatedBy
    #         }
    #     }
    # """

    # variables = {
    #     "permissionId": "666c6f90-a013-11eb-8016-0242ac120002"
    # }

    payload = {"mutation": query, "variables": variables}

    response = auth.auth_graphql(**payload)
    logger.info(response)
