from silvaengine_utility import Utility
from .types import ResourceType, RoleType
from .models import ResourceModel, RoleModel


def resolve_resources(info, **kwargs):
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
                        {"last_evaluated_key": Utility.json_dumps(last_evaluated_key)},
                        **resource.__dict__["attribute_values"]
                    )
                )
            )
        )
        for resource in resources
    ]


def resolve_roles(info, **kwargs):
    limit = kwargs.get("limit")
    last_evaluated_key = kwargs.get("last_evaluated_key")
    role_id = kwargs.get("role_id")

    if role_id is not None:
        role = RoleModel.get(role_id)

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
                        {"last_evaluated_key": Utility.json_dumps(last_evaluated_key)},
                        **role.__dict__["attribute_values"]
                    )
                )
            )
        )
        for role in roles
    ]
