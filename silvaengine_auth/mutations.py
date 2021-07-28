import traceback
from graphene import Field, Mutation
from silvaengine_utility import Utility
from .types import RoleType, RoleInputType
from .handlers import _create_role_handler, _update_role_handler, _delete_role_handler

# Append role info.
class CreateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = _create_role_handler(role_input)
            role = RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(_role.__dict__["attribute_values"])
                )
            )

            return CreateRole(role=role)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Modify role info.
class UpdateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = _update_role_handler(role_input)
            role = RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(_role.__dict__["attribute_values"])
                )
            )

            return UpdateRole(role=role)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Delete role
class DeleteRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _delete_role_handler(role_input)
            return DeleteRole(role=None)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e
