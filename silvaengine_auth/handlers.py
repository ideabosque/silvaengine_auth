from .models import BaseModel, ResourceModel, RoleModel
from datetime import datetime
import uuid


def createRoleHandler(role_input):
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


def updateRoleHandler(role_input):
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


def deleteRoleHandler(role_input):
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
