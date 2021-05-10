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
from .handlers import createRoleHandler, updateRoleHandler, deleteRoleHandler

# Append or modify role info.
class createRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = createRoleHandler(role_input)
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

        return createRole(role=role)


class updateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = updateRoleHandler(role_input)
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

        return updateRole(role=role)


class deleteRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = deleteRoleHandler(role_input)
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

        return deleteRole(role=role)
