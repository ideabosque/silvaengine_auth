from silvaengine_utility import Utility
from .types import LastEvaluatedKey, RoleType, RolesType
from .models import RoleModel


def resolve_roles(info, **kwargs):
    def get_value(results, key, data_type) -> str:
        if (
            results
            and key
            and data_type
            and results.get(key)
            and results.get(key).get(data_type)
        ):
            return results.get(key).get(data_type)

        return ""

    limit = kwargs.get("limit")
    last_evaluated_key = kwargs.get("last_evaluated_key")
    hash_key_field_name = RoleModel._hash_keyname
    range_key_field_name = RoleModel._range_keyname
    hash_key_field_data_type = (
        RoleModel._hash_key_attribute().attr_type[0].upper()
        if RoleModel._hash_key_attribute()
        else None
    )
    range_key_field_data_type = (
        RoleModel._range_key_attribute().attr_type[0].upper()
        if RoleModel._range_key_attribute()
        else None
    )

    if last_evaluated_key:
        values = {}

        for k, v in last_evaluated_key.items():
            key = k.lower()

            if key == "hash_key" and hash_key_field_name and hash_key_field_data_type:
                values[hash_key_field_name] = {hash_key_field_data_type: v}
            elif (
                key == "range_key"
                and range_key_field_name
                and range_key_field_data_type
            ):
                values[range_key_field_name] = {range_key_field_data_type: v}

        results = RoleModel.scan(
            limit=int(limit),
            last_evaluated_key=values,
        )
    else:
        results = RoleModel.scan(limit=int(limit))

    roles = [role for role in results]

    if results.total_count < 1:
        return None

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
            hash_key=get_value(
                results.last_evaluated_key,
                hash_key_field_name,
                hash_key_field_data_type,
            ),
            range_key=get_value(
                results.last_evaluated_key,
                range_key_field_name,
                range_key_field_data_type,
            ),
        ),
    )


def resolve_role(info, **kwargs):
    role_id = kwargs.get("role_id")

    if role_id:
        role = RoleModel.get(role_id)

        return RoleType(
            **Utility.json_loads(Utility.json_dumps(role.__dict__["attribute_values"]))
        )

    return None
