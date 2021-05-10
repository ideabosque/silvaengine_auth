import traceback
from graphene import ObjectType, String, Int, List, Field, Schema, Mutation
from silvaengine_utility import Utility
from .types import (
    ResourceType,
    RoleType,
    ResourceInputType,
    RoleInputType,
    PermissionType,
    PermissionInputType,
)
from .models import BaseModel, ResourceModel, RoleModel
from .handlers import create_role_handler, update_role_handler, delete_role_handler

# Append or modify role info.
class CreateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = create_role_handler(role_input)
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

        return CreateRole(role=role)


class UpdateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = update_role_handler(role_input)
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

        return UpdateRole(role=role)


class DeleteRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            delete_role_handler(role_input)
            # role = RoleType(
            #     **Utility.json_loads(
            #         Utility.json_dumps(_role.__dict__["attribute_values"])
            #     )
            # )
        except Exception:
            log = traceback.format_exc()
            info.context.get("logger").exception(log)
            print("Exception")
            raise

        return DeleteRole(role=None)
