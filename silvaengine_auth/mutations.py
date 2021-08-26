import traceback
from graphene import Field, Mutation, String, Boolean
from silvaengine_utility import Utility
from .types import RoleType, RoleInputType, RelationshipType, RelationshipInputType
from .handlers import (
    _create_role_handler,
    _update_role_handler,
    _delete_role_handler,
    _create_relationship_handler,
    _update_relationship_handler,
    _delete_relationship_handler,
)

# Append role info.
class CreateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_input = RoleInputType(required=True)

    @staticmethod
    def mutate(root, info, role_input=None):
        try:
            _role = _create_role_handler(info, role_input)
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
            _role = _update_role_handler(info, role_input)
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
    ok = Boolean()

    class Arguments:
        role_id = String(required=True)

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            _delete_role_handler(info, kwargs.get("role_id"))
            return DeleteRole(ok=True)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Append role info.
class CreateRelationship(Mutation):
    relationship = Field(RelationshipType)

    class Arguments:
        input = RelationshipInputType(required=True)

    @staticmethod
    def mutate(root, info, input=None):
        try:
            _relationship = _create_relationship_handler(info, input)
            relationship = RelationshipType(
                **Utility.json_loads(
                    Utility.json_dumps(_relationship.__dict__["attribute_values"])
                )
            )

            return CreateRelationship(relationship=relationship)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Modify role info.
class UpdateRelationship(Mutation):
    relationship = Field(RelationshipType)

    class Arguments:
        input = RelationshipInputType(required=True)

    @staticmethod
    def mutate(root, info, input=None):
        try:
            _relationship = _update_relationship_handler(info, input)
            relationship = RelationshipType(
                **Utility.json_loads(
                    Utility.json_dumps(_relationship.__dict__["attribute_values"])
                )
            )

            return UpdateRelationship(relationship=relationship)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Delete relationship
class DeleteRelationship(Mutation):
    ok = Boolean()

    class Arguments:
        relationship_id = String(required=True)

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            _delete_relationship_handler(info, kwargs.get("relationship_id"))
            return DeleteRelationship(ok=True)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e
