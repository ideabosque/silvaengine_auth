from silvaengine_utility import Utility
from .types import LastEvaluatedKey, RoleType, RolesType
from .models import RoleModel


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
        values = {}

        for k, v in last_evaluated_key.items():
            key = k.lower()

            if key == "hash_key" and RoleModel._hash_keyname is not None:
                values[RoleModel._hash_keyname] = {
                    RoleModel._hash_key_attribute().attr_type[0]: v
                }
            elif key == "range_key" and RoleModel._range_keyname is not None:
                values[RoleModel._range_keyname] = {
                    RoleModel._range_key_attribute().attr_type[0]: v
                }

        results = RoleModel.scan(
            limit=int(limit),
            last_evaluated_key=values,
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
