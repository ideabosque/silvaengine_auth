#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from importlib.util import find_spec
from importlib import import_module
from silvaengine_utility import Utility
from jose import jwk, jwt
from .types import (
    RoleType as OutputRoleType,
    RolesType,
    CertificateType,
    UserRelationshipType,
    SimilarUserType,
    SimilarUsersType,
    RoleDetectionType,
)
from .models import RelationshipModel, RoleModel, RoleType
from .handlers import _get_user_permissions
import boto3, os, hmac, hashlib, base64, json


# @TODO: Apply status check
def _resolve_roles(info, **kwargs):
    try:
        arguments = {
            "limit": int(
                kwargs.get(
                    "page_size",
                    info.context.get("setting", {}).get("max_size_per_page", 10),
                )
            ),
            "last_evaluated_key": None,
            "filter_condition": None,
        }
        total = 0

        # Build filter conditions.
        # @SEE: {"ARGUMENT_NAME": "FIELD_NAME_OF_DATABASE_TABLE", ...}
        mappings = {
            "is_admin": "is_admin",
            "name": "name",
            "role_description": "description",
            "role_type": "type",
            "status": "status",
        }
        filter_conditions = []

        # Get filter condition from arguments
        # @TODO: If there is an operation such as `is_in`, this method or mapping must be extended`
        for argument, field in mappings.items():
            if kwargs.get(argument) is None or not hasattr(RoleModel, field):
                continue

            if field == "name":
                filter_conditions.append(
                    (
                        getattr(RoleModel, field).contains(
                            str(kwargs.get(argument)).strip()
                        )
                    )
                )
            else:
                filter_conditions.append(
                    (getattr(RoleModel, field) == kwargs.get(argument))
                )

        if kwargs.get("user_ids"):
            role_ids = [
                str(relationship.role_id).strip()
                for relationship in RelationshipModel.scan(
                    RelationshipModel.role_id.is_in(*list(set(kwargs.get("user_ids"))))
                )
            ]

            if len(role_ids):
                filter_conditions.append((RoleModel.role_id.is_in(*role_ids)))

        if len(filter_conditions):
            arguments["filter_condition"] = filter_conditions.pop(0)

            for condition in filter_conditions:
                arguments["filter_condition"] = (
                    arguments.get("filter_condition") & condition
                )

        # Count total of roles
        for _ in RoleModel.scan(filter_condition=arguments.get("filter_condition")):
            total += 1

        # Pagination.
        if arguments.get("limit") > 0 and kwargs.get("page_number", 0) > 1:
            pagination_arguments = {
                "limit": (int(kwargs.get("page_number", 0)) - 1)
                * arguments.get("limit"),
                "last_evaluated_key": None,
                "filter_condition": arguments.get("filter_condition"),
            }

            # Skip (int(kwargs.get("page_number", 0)) - 1) rows
            pagination_results = RoleModel.scan(**pagination_arguments)
            # Discard the results of the iteration, and extract the cursor of the page offset from the iterator.
            _ = [role for role in pagination_results]
            # The iterator needs to be traversed first, and then the pagination cursor can be obtained through `last_evaluated_key` after the traversal is completed.
            arguments["last_evaluated_key"] = pagination_results.last_evaluated_key

            if (
                arguments.get("last_evaluated_key") is None
                or pagination_results.total_count == total
            ):
                return None

        # Query role form database.
        results = RoleModel.scan(**arguments)
        roles = [
            OutputRoleType(
                **Utility.json_loads(
                    Utility.json_dumps(dict(**role.__dict__["attribute_values"]))
                )
            )
            for role in results
        ]

        if results.total_count < 1:
            return None

        return RolesType(
            items=roles,
            page_number=kwargs.get("page_number", 1),
            page_size=arguments.get("limit"),
            total=total,
        )
    except Exception as e:
        raise e


# @TODO: Apply status check
# Query users by relationship.
def _resolve_users(info, **kwargs):
    try:
        arguments = {
            "limit": int(
                kwargs.get(
                    "page_size",
                    info.context.get("setting", {}).get("max_size_per_page", 10),
                )
            ),
            "last_evaluated_key": None,
            "filter_condition": None,
        }
        total = 0
        # Build filter conditions.
        # @SEE: {"ARGUMENT_NAME": "FIELD_NAME_OF_DATABASE_TABLE", ...}
        # Role model
        role_field_argument_mappings_eq = {
            "role_status": "status",
            "is_admin_role": "is_admin",
        }
        role_field_argument_mappings_in = {
            "role_type": "type",
            "role_name": "name",
            "role_id": "role_id",
        }
        role_filter_conditions = []

        # eq: Get filter condition from arguments for Roles
        for argument, field in role_field_argument_mappings_eq.items():
            if kwargs.get(argument) is None or not hasattr(RoleModel, field):
                continue

            role_filter_conditions.append(
                (getattr(RoleModel, field) == kwargs.get(argument))
            )

        # in: Get filter condition from arguments for Roles
        for argument, field in role_field_argument_mappings_in.items():
            if (
                not hasattr(RoleModel, field)
                or type(kwargs.get(argument)) is not list
                or len(kwargs.get(argument, [])) < 1
            ):
                continue

            role_filter_conditions.append(
                (getattr(RoleModel, field).is_in(*kwargs.get(argument)))
            )

        # Join the filter conditions
        if len(role_filter_conditions):
            arguments["filter_condition"] = role_filter_conditions.pop(0)

            for condition in role_filter_conditions:
                arguments["filter_condition"] = (
                    arguments["filter_condition"] & condition
                )

        # Pagination.
        if arguments.get("limit") > 0 and kwargs.get("page_number", 0) > 1:
            pagination_arguments = {
                "limit": (int(kwargs.get("page_number", 0)) - 1)
                * arguments.get("limit"),
                "last_evaluated_key": None,
                "filter_condition": arguments["filter_condition"],
            }

            # Skip (int(kwargs.get("page_number", 0)) - 1) rows
            pagination_results = RoleModel.scan(**pagination_arguments)
            # Discard the results of the iteration, and extract the cursor of the page offset from the iterator.
            _ = [role for role in pagination_results]
            arguments["last_evaluated_key"] = pagination_results.last_evaluated_key

            if (
                arguments.get("last_evaluated_key") is None
                or pagination_results.total_count == total
            ):
                return None

        # Count total of roles
        roles = {}

        for role in RoleModel.scan(**arguments):
            if role:
                roles[role.role_id] = SimilarUserType(
                    users=[],
                    **Utility.json_loads(
                        Utility.json_dumps(dict(**role.__dict__["attribute_values"]))
                    )
                )
                total += 1

        if (
            kwargs.get("role_id") and roles.get(kwargs.get("role_id")) is None
        ) or total == 0:
            return None

        relatinship_filter_conditions = [
            (RelationshipModel.role_id.is_in(*roles.keys()))
        ]
        # Relationship model
        relationship_field_argument_mappings_eq = {
            "relationship_status": "status",
            "relationship_type": "type",
        }
        relationship_field_argument_mappings_in = {
            "owner_id": "group_id",
        }

        # eq: Get filter condition from arguments
        for argument, field in relationship_field_argument_mappings_eq.items():
            if kwargs.get(argument) is None or not hasattr(RelationshipModel, field):
                continue

            relatinship_filter_conditions.append(
                (getattr(RelationshipModel, field) == kwargs.get(argument))
            )

        # in: Get filter condition from arguments
        for argument, field in relationship_field_argument_mappings_in.items():
            if (
                not hasattr(RelationshipModel, field)
                or type(kwargs.get(argument)) is not list
                or len(kwargs.get(argument, [])) < 1
            ):
                continue

            relatinship_filter_conditions.append(
                (getattr(RelationshipModel, field).is_in(*kwargs.get(argument)))
            )

        # Join the filter conditions
        filter_condition = None

        if len(relatinship_filter_conditions):
            filter_condition = relatinship_filter_conditions.pop(0)

            for condition in relatinship_filter_conditions:
                filter_condition = filter_condition & condition

        # Query data from the database.
        results = RelationshipModel.scan(filter_condition=filter_condition)
        relationships = [
            UserRelationshipType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        dict(**relationship.__dict__["attribute_values"])
                    )
                )
            )
            for relationship in results
        ]

        if results.total_count < 1:
            return None

        hooks = (
            [
                hook.strip()
                for hook in info.context.get("setting", {})
                .get("custom_hooks", "")
                .split(",")
            ]
            if info.context.get("setting", {}).get("custom_hooks")
            else []
        )

        if len(hooks):
            logger = info.context.get("logger")

            for hook in hooks:
                fragments = hook.split(":", 3)

                if len(fragments) < 3:
                    for i in (0, 3 - len(fragments)):
                        fragments.append(None)
                elif len(fragments) > 3:
                    fragments = fragments[0:3]

                module_name, class_name, function_name = fragments
                fn = Utility.import_dynamically(
                    module_name, function_name, class_name, {"logger": logger}
                )

                if fn is None:
                    continue

                users = fn(
                    list(set([relationship.user_id for relationship in relationships]))
                )

                if len(users):
                    for relationship in relationships:
                        user_ids = list(
                            set(
                                [
                                    # user.cognito_user_sub
                                    str(user["id"])
                                    for user in roles[
                                        str(relationship.role_id).strip()
                                    ].users
                                    # if hasattr(user, "cognito_user_sub")
                                    if ("id" in user)
                                ]
                            )
                        )

                        if (
                            relationship.role_id
                            and roles.get(str(relationship.role_id).strip())
                            and relationship.user_id
                            and users.get(str(relationship.user_id).strip())
                            and str(relationship.user_id).strip() not in user_ids
                        ):

                            roles[str(relationship.role_id).strip()].users.append(
                                users.get(str(relationship.user_id).strip())
                            )

                        # items.append(relationship)

                # relationships = items

        return SimilarUsersType(
            items=roles.values(),
            page_number=kwargs.get("page_number", 1),
            page_size=arguments.get("limit"),
            total=total,
        )
    except Exception as e:
        raise e


# Query role info by specified ID.
def _resolve_role(info, **kwargs):
    role = RoleModel.get(kwargs.get("role_id"))

    return OutputRoleType(
        **Utility.json_loads(Utility.json_dumps(role.__dict__["attribute_values"]))
    )


# Login
def _resolve_certificate(info, **kwargs):
    try:
        username = kwargs.get("username")
        password = kwargs.get("password")

        assert username or password, "Username or password is required"

        settings = info.context.get("setting", {})

        region_name = (
            settings.get("region_name")
            if settings.get("region_name")
            else os.getenv("REGIONNAME")
        )
        aws_access_key_id = (
            settings.get("aws_access_key_id")
            if settings.get("aws_access_key_id")
            else os.getenv("aws_access_key_id")
        )
        aws_secret_access_key = (
            settings.get("aws_secret_access_key")
            if settings.get("aws_secret_access_key")
            else os.getenv("aws_secret_access_key")
        )
        app_client_id = (
            settings.get("app_client_id")
            if settings.get("app_client_id")
            else os.getenv("app_client_id")
        )
        app_client_secret = (
            settings.get("app_client_secret")
            if settings.get("app_client_secret")
            else os.getenv("app_client_secret")
        )

        if (
            not region_name
            or not aws_access_key_id
            or not aws_secret_access_key
            or not app_client_id
            or not app_client_secret
        ):
            raise Exception("Missing required configuration", 400)

        cognitoIdp = boto3.client(
            "cognito-idp",
            region_name=region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        digest = hmac.new(
            key=app_client_secret.encode("utf-8"),
            msg=(username + app_client_id).encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        response = cognitoIdp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": base64.b64encode(digest).decode(),
            },
            ClientId=app_client_id,
        )

        if not response or not response.get("AuthenticationResult", {}).get("IdToken"):
            raise Exception("Failed to sign in on cognito")

        # @TODO: hooks
        hooks = (
            [
                hook.strip()
                for hook in settings.get(
                    "custom_signin_hooks",
                ).split(",")
            ]
            if settings.get("custom_signin_hooks")
            else []
        )
        # hooks = ["relation_engine:RelationEngine:get_default_for_login"]
        token_claims = jwt.get_unverified_claims(
            response.get("AuthenticationResult").get("IdToken")
        )

        if token_claims.get("teams"):
            token_claims.pop("teams")

        if len(hooks):
            logger = info.context.get("logger")

            for hook in hooks:
                fragments = hook.split(":", 3)

                if len(fragments) < 3:
                    for i in (0, 3 - len(fragments)):
                        fragments.append(None)
                elif len(fragments) > 3:
                    fragments = fragments[0:3]

                module_name, class_name, function_name = fragments

                # 1. Load module by dynamic
                spec = find_spec(module_name)

                if spec is None:
                    continue

                agent = import_module(module_name)

                if hasattr(agent, class_name):
                    agent = getattr(agent, class_name)(logger)

                if not hasattr(agent, function_name):
                    continue

                result = getattr(agent, function_name)(token_claims)

                if type(result) is dict:
                    token_claims.update(result)

        return CertificateType(
            access_token=response.get("AuthenticationResult").get("AccessToken"),
            id_token=response.get("AuthenticationResult").get("IdToken"),
            refresh_token=response.get("AuthenticationResult").get("RefreshToken"),
            expires_in=response.get("AuthenticationResult").get("ExpiresIn"),
            token_type=response.get("AuthenticationResult").get("TokenType"),
            context=token_claims,
            permissions=_get_user_permissions(token_claims),
        )
    except Exception as e:
        raise e


# Role uniqueness detection
def _resolve_detection(info, **kwargs):
    role_name = kwargs.get("name")

    filter_conditions = (
        ((RoleModel.name == role_name))
        if role_name is not None and role_name != ""
        else (
            (
                RoleModel.type.is_in(
                    *[
                        RoleType.ACCOUNT_MANAGER.value,
                        RoleType.QC_MANAGER.value,
                        RoleType.DEPT_MANAGER.value,
                    ]
                )
            )
        )
    )

    types = {
        t.value: {
            "type_alias": t.name,
            "is_exclusive": t.value != RoleType.NORMAL.value,
            "roles": [],
        }
        for t in RoleType
    }
    roles = {}

    for role in RoleModel.scan(filter_condition=filter_conditions):
        role = role.__dict__["attribute_values"]

        if role.get("type") is not None:
            if roles.get(role.get("type")) is None and types.get(role.get("type")):
                roles[role.get("type")] = types.get(role.get("type"))

            if (
                roles.get(role.get("type")) is not None
                and type(roles[role.get("type")].get("roles")) is list
            ):
                roles[role.get("type")]["roles"].append(
                    {
                        "name": role.get("name", ""),
                    }
                )

    return RoleDetectionType(roles=roles)
