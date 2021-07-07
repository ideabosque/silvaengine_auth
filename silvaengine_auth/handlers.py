from .models import RoleModel
from datetime import datetime
import uuid


def create_role_handler(role_input):
    # Insert a role record.
    role_id = str(uuid.uuid1())
    RoleModel(
        role_id,
        **{
            "name": role_input.name,
            "is_admin": role_input.is_admin,
            "description": role_input.description,
            "permissions": role_input.permissions,
            "user_ids": role_input.user_ids,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "updated_by": role_input.updated_by,
        }
    ).save()

    return RoleModel.get(role_id)


def update_role_handler(role_input):
    assert role_input.role_id, "Role id is required"

    # Update the role record.
    role = RoleModel.get(role_input.role_id)
    role.update(
        actions=[
            RoleModel.updated_at.set(datetime.utcnow()),
            RoleModel.updated_by.set(role_input.updated_by),
            RoleModel.name.set(role_input.name),
            RoleModel.is_admin.set(role_input.is_admin),
            RoleModel.description.set(role_input.description),
            RoleModel.permissions.set(role_input.permissions),
            RoleModel.user_ids.set(role_input.user_ids),
        ]
    )
    return RoleModel.get(role_input.role_id)


def delete_role_handler(role_input):
    assert role_input.role_id, "Role id is required"

    # Delete the role record.

    return RoleModel(role_input.role_id).delete()


def add_resource():
    with open("f:\install.log", "a") as fd:
        print("mtest")
        fd.write("Test\n")
