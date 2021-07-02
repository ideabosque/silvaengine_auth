from silvaengine_utility import Utility
from .types import LastEvaluatedKey, RoleType, RolesType
from .models import RoleModel


def resolve_roles(info, **kwargs):
    limit = kwargs.get("limit")
    last_evaluated_key = kwargs.get("last_evaluated_key")
    role_id = kwargs.get("role_id")

    print(last_evaluated_key)

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
    else:
        results = RoleModel.scan(limit=int(limit))

    roles = [role for role in results]

    return RolesType(
        items=[
            RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(dict(**role.__dict__["attribute_values"]))
                )
            )
            for role in roles
        ],
        last_evaluated_key=LastEvaluatedKey(
            hash_key=results.last_evaluated_key.get("role_id").get("S"),
        ),
    )
