#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from datetime import datetime
from jose import jwk, jwt
from jose.utils import base64url_decode
from jose.constants import ALGORITHMS
from hashlib import md5
from importlib.util import find_spec
from importlib import import_module
from silvaengine_utility import Utility, Graphql, Authorizer
from silvaengine_resource import ResourceModel
from pynamodb.transactions import TransactWrite
from pynamodb.connection import Connection
from .utils import validate_required, get_seller_id, is_admin_user
from .models import (
    ConnectionModel,
    RelationshipModel,
    RoleModel,
    ConfigDataModel,
    RoleRelationshipType,
    RoleType,
)
import uuid, json, time, urllib.request, os


# Create role
def _create_role_handler(info, kwargs):
    try:
        role_id = str(uuid.uuid1())
        now = datetime.utcnow()

        RoleModel(
            role_id,
            **{
                "name": kwargs.get("name"),
                "type": int(kwargs.get("role_type", 0)),
                "is_admin": bool(kwargs.get("is_admin", True)),
                "permissions": kwargs.get("permissions", []),
                "description": kwargs.get("role_description"),
                "status": bool(kwargs.get("status", True)),
                "updated_by": kwargs.get("updated_by"),
                "created_at": now,
                "updated_at": now,
            },
        ).save()

        return RoleModel.get(role_id, None)
    except Exception as e:
        raise e


# Update role for specified ID.
def _update_role_handler(info, kwargs):
    try:
        role = RoleModel(kwargs.get("role_id"))
        actions = [
            RoleModel.updated_at.set(datetime.utcnow()),
        ]
        rules = {
            "name": "name",
            "is_admin": "is_admin",
            "role_type": "type",
            "role_description": "description",
            "permissions": "permissions",
            "status": "status",
            "updated_by": "updated_by",
        }

        for argument, field in rules.items():
            if kwargs.get(argument) is not None:
                actions.append(getattr(RoleModel, field).set(kwargs.get(argument)))

        condition = RoleModel.role_id == kwargs.get("role_id")

        role.update(
            actions=actions,
            condition=condition,
        )

        return RoleModel.get(kwargs.get("role_id"), None)
    except Exception as e:
        raise e


# Delete role by specified ID.
def _delete_role_handler(info, role_id):
    try:
        if role_id is None or str(role_id).strip() == "":
            raise Exception("`roleId` is required", 400)

        condition = RoleModel.role_id == role_id

        # Delete the role record.
        return RoleModel(role_id).delete(condition=condition)
    except Exception as e:
        raise e


# Create relationship of role / group / user.
def _create_relationship_handler(info, kwargs):
    try:
        relationship_id = str(uuid.uuid1())
        now = datetime.utcnow()
        filter_conditions = (
            (RelationshipModel.type == int(kwargs.get("relationship_type", 0)))
            & (RelationshipModel.user_id == str(kwargs.get("user_id")).strip())
            & (RelationshipModel.role_id == str(kwargs.get("role_id")).strip())
            & (RelationshipModel.group_id == str(kwargs.get("group_id")).strip())
        )
        relationship_ids = list(
            set(
                [
                    str(item.relationship_id).strip()
                    for item in RelationshipModel.scan(
                        filter_condition=filter_conditions
                    )
                ]
            )
        )

        if len(relationship_ids):
            actions = [
                RelationshipModel.updated_at.set(now),
                RelationshipModel.updated_by.set(
                    str(
                        kwargs.get(
                            "updated_by",
                            info.context.get("authorizer", {}).get("user_id", "setup"),
                        )
                    ).strip()
                ),
            ]
            rules = {
                "relationship_type": {"field": "type", "type": "int"},
                "user_id": {"field": "user_id", "type": "str"},
                "role_id": {"field": "role_id", "type": "str"},
                "group_id": {"field": "group_id", "type": "str"},
                "status": {"field": "status", "type": "bool"},
            }

            for argument, rule in rules.items():
                if kwargs.get(argument) is not None and hasattr(
                    RelationshipModel, rule.get("field")
                ):
                    value = kwargs.get(argument)

                    if rule.get("type") == "int":
                        value = int(value)
                    elif rule.get("type") == "str":
                        value = str(value).strip()
                    elif rule.get("type") == "bool":
                        value = bool(value)

                    actions.append(
                        getattr(RelationshipModel, rule.get("field")).set(value)
                    )

            for id in relationship_ids:
                RelationshipModel(id).update(
                    actions=actions,
                    condition=RelationshipModel.relationship_id.is_in(
                        *relationship_ids
                    ),
                )

            relationship_id = relationship_ids[0]
        else:
            RelationshipModel(
                relationship_id,
                **{
                    "type": int(kwargs.get("relationship_type", 0)),
                    "user_id": str(kwargs.get("user_id")).strip(),
                    "role_id": str(kwargs.get("role_id")).strip(),
                    "group_id": str(kwargs.get("group_id")).strip(),
                    "created_at": now,
                    "updated_at": now,
                    "updated_by": str(
                        kwargs.get(
                            "updated_by",
                            info.context.get("authorizer", {}).get("user_id", "setup"),
                        )
                    ).strip(),
                    "status": bool(kwargs.get("status", True)),
                },
            ).save()

        # print("Save successful:", relationship_id)
        return RelationshipModel.get(relationship_id)
    except Exception as e:
        raise e


# Update relationship for specified ID.
def _update_relationship_handler(info, kwargs):
    try:
        relationship = RelationshipModel(kwargs.get("relationship_id"))
        actions = [
            RelationshipModel.updated_at.set(datetime.utcnow()),
        ]
        fields = {
            "relationship_type": "type",
            "user_id": "user_id",
            "role_id": "role_id",
            "group_id": "group_id",
            "is_admin": "is_admin",
            "updated_by": "updated_by",
            "status": "status",
        }
        need_update = False

        for argument, field in fields.items():
            if kwargs.get(argument) is not None:
                need_update = True

                actions.append(
                    getattr(RelationshipModel, field).set(kwargs.get(argument))
                )

        if need_update:
            condition = RelationshipModel.relationship_id == kwargs.get(
                "relationship_id"
            )
            relationship.update(
                actions=actions,
                condition=condition,
            )

        return RelationshipModel.get(kwargs.get("relationship_id"))
    except Exception as e:
        raise e


# Delete relationship by specified ID.
def _delete_relationship_handler(info, relationship_id):
    try:
        if relationship_id is None or str(relationship_id).strip() == "":
            raise Exception("`relationshipId` is required", 400)

        # Delete the group/user/role relationship.
        print("DELETE RELATIONSHIP >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print(relationship_id)
        return RelationshipModel(relationship_id).delete()
    except Exception as e:
        raise e


# Bulk save relationships
def _save_relationships_handler(info, relationships):
    try:
        if (
            relationships is None
            or type(relationships) is not list
            or len(relationships) < 1
        ):
            raise Exception("`relationships` is required", 400)

        now = datetime.utcnow()

        for relationship in relationships:
            if (
                relationship.get("type") is None
                or not relationship.get("user_id")
                or not relationship.get("role_id")
                or (
                    int(relationship.get("type", 0)) != 0
                    and not relationship.get("group_id")
                )
            ):
                raise Exception("Bad reqeust", 400)

            filter_conditions = (
                RelationshipModel.type == int(relationship.get("type", 0))
            ) & (RelationshipModel.user_id == str(relationship.get("user_id")).strip())

            if int(relationship.get("type", 0)) != 0 and relationship.get("group_id"):
                filter_conditions = filter_conditions & (
                    RelationshipModel.group_id
                    == str(relationship.get("group_id")).strip()
                )

            for item in RelationshipModel.scan(filter_condition=filter_conditions):
                _delete_relationship_handler(info, str(item.relationship_id).strip())

        for relationship in relationships:
            RelationshipModel(
                str(uuid.uuid1()),
                **{
                    "type": int(relationship.get("type", 0)),
                    "user_id": str(relationship.get("user_id")).strip(),
                    "role_id": str(relationship.get("role_id")).strip(),
                    "group_id": str(relationship.get("group_id")).strip(),
                    "created_at": now,
                    "updated_at": now,
                    "updated_by": str(
                        relationship.get(
                            "updated_by",
                            info.context.get("authorizer", {}).get("user_id", "setup"),
                        )
                    ).strip(),
                    "status": bool(relationship.get("status", True)),
                },
            ).save()

    except Exception as e:
        raise e


# Verify ip whitelist
def _verify_whitelist(event, context) -> bool:
    try:
        if (
            not event.get("requestContext").get("identity").get("sourceIp")
            or not event.get("requestContext").get("identity").get("apiKey")
            or not event.get("pathParameters").get("endpoint_id")
        ):
            return False

        endpoint_id = event.get("pathParameters").get("endpoint_id")
        api_key = event.get("requestContext").get("identity").get("apiKey")
        connnection = ConnectionModel.get(endpoint_id, api_key)

        if connnection and connnection.whitelist and len(connnection.whitelist):
            source_ip = (
                event.get("requestContext").get("identity").get("sourceIp").strip()
            )

            for ip in connnection.whitelist:
                if Utility.in_subnet(source_ip, ip.strip()):
                    return True

        return False
    except Exception as e:
        raise e


# Verify token
def _verify_token(settings, event) -> dict:
    try:
        claims = None

        if event.get("fnConfigurations").get("config").get("auth_required"):
            headers = dict(
                (key.strip().lower(), value)
                for key, value in event.get("headers").items()
            )

            if not headers.get("authorization"):
                raise Exception(f"Token is required", 400)

            token = headers.get("authorization")
            claims = jwt.get_unverified_claims(token)
            required_setting_keys = ["region_name", "user_pool_id", "app_client_id"]

            for key in required_setting_keys:
                if settings.get(key) is None:
                    raise Exception(f"{key} is required", 400)

            # keys_url = (
            #     "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
            #         settings.get("region_name"), settings.get("user_pool_id")
            #     )
            # )

            # print(keys_url)

            # # instead of re-downloading the public keys every time
            # # we download them only on cold start
            # # https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
            # with urllib.request.urlopen(keys_url) as f:
            #     response = f.read()

            # print(response)
            # keys = json.loads(response.decode("utf-8"))["keys"]
            # print(keys)
            # print("TOKEN:", token)
            # # get the kid from the headers prior to verification
            # headers = jwt.get_unverified_headers(token)
            # kid = headers["kid"]
            # print("KIDKIDKIDKIDKIDKIDKIDKID:", kid)
            # # search for the kid in the downloaded public keys
            # key_index = -1

            # for i in range(len(keys)):
            #     if kid == keys[i]["kid"]:
            #         key_index = i
            #         break

            # if key_index == -1:
            #     print("Public key not found in jwks.json")
            #     raise Exception("Public key not found in jwks.json", 401)

            # # construct the public key
            # print(key_index, keys[key_index], type(keys[key_index]))
            # algorithm = (
            #     keys[key_index].get("alg")
            #     if keys[key_index].get("alg")
            #     else ALGORITHMS.RS256
            # )
            # keys[key_index]["alg"] = ALGORITHMS.RS256
            # public_key = jwk.construct(keys[key_index], algorithm)

            # if public_key is None:
            #     raise Exception("Public key is invalid", 401)

            # print(type(public_key), public_key)
            # # get the last two sections of the token,
            # # message and signature (encoded in base64)
            # message, encoded_signature = str(token).rsplit(".", 1)
            # # decode the signature
            # decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

            # # verify the signature
            # if not public_key.verify(message.encode("utf8"), decoded_signature):
            #     print("Signature verification failed")
            #     raise Exception("Signature verification failed", 401)

            # since we passed the verification, we can now safely
            # use the unverified claims

            # additionally we can verify the token expiration
            if time.time() > claims["exp"]:
                raise Exception("Token is expired", 401)

            # and the Audience  (use claims['client_id'] if verifying an access token)
            app_client_ids = [
                str(id).strip().lower()
                for id in settings.get("app_client_id").split(",")
            ]

            if not app_client_ids.__contains__(claims["aud"].strip().lower()):
                raise Exception("Token was not issued for this audience", 401)

        return claims
    except Exception as e:
        raise e


# Verify resource permission
def _verify_permission(event, context):
    try:
        if (
            not event.get(
                "fnConfigurations",
            )
            .get("config", {})
            .get("auth_required")
            or event.get("requestContext", {})
            .get("authorizer", {})
            .get("is_allowed_by_whitelist")
            == "1"
        ):
            return event

        # not event.get("requestContext", {}).get("authorizer", {}).get("sub")
        if (
            not event.get("pathParameters", {}).get("proxy")
            or not event.get("headers")
            or not event.get("body")
            or not event.get("fnConfigurations")
            or not event.get("requestContext", {}).get("authorizer", {}).get("user_id")
        ):
            raise Exception("Event is missing required parameters", 500)

        headers = dict(
            (key.strip().lower(), value) for key, value in event.get("headers").items()
        )
        function_config = event.get("fnConfigurations")
        authorizer = event.get("requestContext").get("authorizer")
        body = event.get("body")
        function_name = event.get("pathParameters").get("proxy").strip()
        content_type = headers.get("content-type")
        area = event.get("pathParameters").get("area")
        endpoint_id = event.get("pathParameters").get("endpoint_id")
        message = f"Don't have the permission to access at /{area}/{endpoint_id}/{function_name}."
        # method = event["httpMethod"]
        is_admin = (
            bool(int(authorizer.get("is_admin")))
            if authorizer.get("is_admin")
            else False
        )
        # uid = authorizer.get("sub")
        uid = authorizer.get("user_id")
        owner_id = (
            str(authorizer.get("seller_id")).strip()
            if authorizer.get("seller_id")
            else ""
        )
        team_id = headers.get("team_id")

        event["requestContext"]["authorizer"].update(
            {
                "seller_id": headers.get("seller_id").strip()
                if headers.get("seller_id") and is_admin
                else owner_id,
                "team_id": team_id.strip() if team_id else None,
            }
        )

        if content_type and content_type.strip().lower() == "application/json":
            body_json = json.loads(body)

            if "query" in body_json:
                body = body_json["query"]

        if not function_config.get("config").get("operations"):
            raise Exception(message, 403)

        function_operations = function_config.get("config").get("operations")

        if not function_config.get("config").get(
            "module_name"
        ) or not function_config.get("config").get("class_name"):
            raise Exception(message, 403)

        # Parse the graphql request's body to AST and extract fields from the AST
        flatten_ast = Graphql.extract_flatten_ast(body)
        # print(flatten_ast, Utility.json_dumps(flatten_ast))
        if type(flatten_ast) is not list and len(flatten_ast) < 1:
            raise Exception(message, 403)

        # Check user's permissions
        relationship_filter_conditions = RelationshipModel.user_id == uid

        if is_admin == False:
            relationship_filter_conditions = (RelationshipModel.user_id == uid) & (
                RelationshipModel.group_id == team_id
            )

        role_ids = [
            relationship.role_id
            for relationship in RelationshipModel.scan(relationship_filter_conditions)
        ]

        if len(role_ids) < 1:
            raise Exception("The user is not assigned any roles", 400)

        roles = [role for role in RoleModel.scan(RoleModel.role_id.is_in(*role_ids))]

        if len(roles) < 1:
            raise Exception("The user is not assigned any roles", 400)

        for item in flatten_ast:
            if not item.get("operation_name"):
                default = ""

                if type(item.get("fields", {}).get("/")) is list and len(
                    item.get("fields", {}).get("/")
                ):
                    default = item.get("fields", {}).get("/")[0]

                item["operation_name"] = default

            operation_name = item.get("operation_name", "")
            operation = item.get("operation", "")

            # Check the operation type is be included by function settings
            if (
                not function_operations.get(operation)
                or type(function_operations.get(operation)) is not list
            ):
                raise Exception(message, 403)

            function_operations = list(
                set(
                    [
                        operation_name.strip().lower()
                        for operation_name in function_operations.get(operation)
                    ]
                )
            )

            if (
                operation_name.strip().lower() not in function_operations
            ) or not _check_permission(roles, item):
                raise Exception(message, 403)

        # Attatch additional info to context
        if uid:
            additional_context = {
                "roles": [
                    {"role_id": role.role_id, "name": role.name} for role in roles
                ]
            }

            # Append hooks result to context
            if authorizer.get("custom_context_hooks"):
                additional_context.update(_execute_custom_hooks(authorizer))

            event["requestContext"]["additionalContext"] = additional_context

            return event

        raise Exception(message, 403)
    except Exception as e:
        raise e


def _authorize_response(event, context):
    try:
        headers = dict(
            (key.strip().lower(), value) for key, value in event.get("headers").items()
        )
        principal = event.get("path")
        api_id = event.get("requestContext", {}).get("apiId")
        method_arn_fragments = event.get("methodArn").split(":")
        api_gateway_arn_fragments = method_arn_fragments[5].split("/")
        region = method_arn_fragments[3]
        aws_account_id = method_arn_fragments[4]
        stage = api_gateway_arn_fragments[1]
        area = api_gateway_arn_fragments[3]
        endpoint_id = api_gateway_arn_fragments[4]
        # request_method = str(event.get("requestContext").get("httpMethod")).upper()
        authorizer = Authorizer(principal, aws_account_id, api_id, region, stage)
        ctx = {}

        if headers.get("seller_id"):
            ctx["seller_id"] = str(headers.get("seller_id", "")).strip()

        if headers.get("team_id"):
            ctx["team_id"] = str(headers.get("team_id", "")).strip()

        ### 1. Verify source ip
        if _verify_whitelist(event, context):
            ctx.update({"is_allowed_by_whitelist": 1})

            return authorizer.authorize(is_allow=True, context=ctx)

        ### 2. Verify user token
        # @TODO: Should fix the setting id name style.
        settings = dict(
            (item.variable, item.value)
            for item in ConfigDataModel.query(f"{stage}_{area}_{endpoint_id}", None)
        )

        if len(settings.keys()) < 1:
            raise Exception("Missing required configuration(s)", 500)

        additional_context = _verify_token(settings, event)

        if additional_context is None:
            additional_context = ctx
        else:
            if additional_context.get("is_admin") is None:
                raise Exception("Missing required item of token", 400)

            if bool(int(additional_context.get("is_admin", 0).strip())) == False:
                if (
                    additional_context.get("seller_id") is None
                    or headers.get("seller_id") is None
                    or additional_context.get("teams") is None
                    or headers.get("team_id") is None
                ):
                    raise Exception("Missing required parameter(s)", 400)
                elif additional_context.get("seller_id") != headers.get("seller_id"):
                    raise Exception("Access exceeded", 403)
                else:
                    teams = dict(**Utility.json_loads(additional_context.get("teams")))
                    team_id = headers.get("team_id").strip()

                    if teams.get(team_id) is None:
                        raise Exception("Access exceeded", 403)

                    additional_context.pop("teams")
                    additional_context.update(teams.get(team_id))
            else:
                additional_context.update(ctx)

        # Append the custom context hooks setting to context
        if settings.get("custom_context_hooks"):
            additional_context.update(
                {
                    "custom_context_hooks": settings.get("custom_context_hooks"),
                }
            )

        return authorizer.authorize(is_allow=True, context=additional_context)
    except Exception as e:
        raise e


# Execute custom hooks by setting
def _execute_custom_hooks(authorizer):
    try:
        if authorizer.get("custom_context_hooks"):
            hooks = [
                str(hook).strip()
                for hook in str(authorizer.get("custom_context_hooks")).split(",")
            ]
            context = {}

            # @TODO: exec by async
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
                    agent = getattr(agent, class_name)()

                if not hasattr(agent, function_name):
                    continue

                context.update(getattr(agent, function_name)(authorizer))

            return context

        return None
    except Exception as e:
        raise e


# Get a list of resource permissions for a specified user
def _get_user_permissions(authorizer):
    try:
        is_admin = (
            bool(int(authorizer.get("is_admin")))
            if authorizer.get("is_admin")
            else False
        )
        # cognito_user_sub = authorizer.get("sub")
        user_id = authorizer.get("user_id")

        if not user_id:
            return None

        # Query user / group / role relationships
        role_ids = [
            relationship.role_id
            for relationship in RelationshipModel.scan(
                RelationshipModel.user_id == user_id
            )
        ]

        if len(role_ids) < 1:
            return None

        rules = []
        result = {}

        for role in RoleModel.scan(RoleModel.role_id.is_in(*role_ids)):
            rules += role.permissions

        resources = {}
        resource_ids = list(set([str(rule.resource_id).strip() for rule in rules]))

        if len(resource_ids) < 1:
            return None

        for resource in ResourceModel.scan(
            ResourceModel.resource_id.is_in(*resource_ids)
        ):
            resources[resource.resource_id] = resource

        for rule in rules:
            resource_id = rule.resource_id.strip()
            resource = resources.get(resource_id)

            if (
                not resource_id
                or not hasattr(resource, "function")
                or not hasattr(resource, "operations")
            ):
                continue

            function_name = getattr(resource, "function")
            # operations = getattr(resource, "operations")
            # print(operations)

            if not result.get(function_name):
                result[function_name] = []
                # result[function_name] = {}

            if type(rule.permissions):
                for permission in rule.permissions:
                    if (
                        permission.operation
                        and permission.operation_name
                        and permission.operation != ""
                        and permission.operation_name != ""
                    ):
                        # action = permission.operation.strip().lower()

                        # if not result.get(function_name).get(action):
                        #     result[function_name][action] = []

                        result[function_name].append(
                            permission.operation_name.strip().lower()
                        )

                        # result[function_name][action].append(
                        #     permission.operation_name.strip().lower()
                        # )

                        # result[function_name][action] = list(
                        #     set(result[function_name][action])
                        # )
            result[function_name] = list(set(result[function_name]))

        return result
    except Exception as e:
        raise e


def _check_permission(roles, resource) -> bool:
    if (
        not resource.get("operation")
        or not resource.get("operation_name")
        or not resource.get("fields")
    ):
        return False

    permissions = []

    for role in roles:
        if (
            not role.permissions
            or not role.role_id
            or type(role.permissions) is not list
            or len(role.permissions) < 1
        ):
            continue

        permissions += role.permissions

    rules = []

    for permission in permissions:
        if (
            not permission.permissions
            or not permission.resource_id
            or type(permission.permissions) is not list
            or len(permission.permissions) < 1
        ):
            continue

        rules += permission.permissions

    m = {}
    request_operation = resource.get("operation").strip().lower()
    request_operation_name = resource.get("operation_name").strip().lower()
    request_fields = resource.get("fields")

    for rule in rules:
        if (
            not rule.operation
            or not rule.operation_name
            or request_operation != rule.operation.strip().lower()
        ):
            continue

        operation_name = rule.operation_name.strip().lower()

        if not m.get(operation_name):
            m[operation_name] = []

        if type(rule.exclude) is list and len(rule.exclude):
            m[operation_name] = list(set(m[operation_name] + rule.exclude))

    if type(m.get(request_operation_name)) is list:
        for field in m.get(request_operation_name):
            path, field = field.strip().lower().split(":", 2)

            if (
                path
                and field
                and path != ""
                and field != ""
                and request_fields.get(path)
                and field.strip().lower() in request_fields.get(path)
            ):
                return False

        return True

    return False


def _convert_permisson_as_dict(permissions):
    if type(permissions) is not list or len(permissions) < 1:
        return None

    # permissions = [
    #     {
    #         "permissions": [
    #             {"exclude": [], "operation_name": "paginateProducts"},
    #             {"exclude": [], "operation_name": "showProduct"},
    #         ],
    #         "resource_id": "053429072013b1fc6eeac9555cd4618b",
    #     }
    # ]
    permission_map = {}

    for rule in permissions:
        if (
            not rule.get("permissions")
            or not rule.get("resource_id")
            or type(rule.get("permissions")) is not list
            or len(rule.get("permissions")) < 1
        ):
            continue

        resource_id = str(rule.get("resource_id")).strip()
        permission_map[resource_id] = {}

        for permission in rule.get("permissions"):
            if not permission.get("operation_name"):
                continue

            operation_name = str(permission.get("operation_name")).strip()
            permission_map[resource_id][operation_name] = (
                permission.get("exclude")
                if type(permission.get("exclude")) is list
                and len(permission.get("exclude"))
                else []
            )

    return permission_map


# Obtain user roles according to the specified user ID
def _get_roles_by_cognito_user_sub(
    user_id, relationship_type, group_id=None, ignore_permissions=True
):
    # 1. If user or relationship type is empty
    if not user_id or str(user_id).strip() == "" or relationship_type is None:
        return []

    arguments = {
        "limit": None,
        "filter_condition": (RelationshipModel.user_id == str(user_id).strip())
        & (RelationshipModel.type == int(relationship_type)),
    }

    if group_id and str(group_id).strip() != "":
        arguments["filter_condition"] = arguments["filter_condition"] & (
            RelationshipModel.group_id == str(group_id).strip()
        )

    role_ids = []
    group_roles = {}

    for relationship in RelationshipModel.scan(**arguments):
        if relationship.role_id:
            rid = str(relationship.role_id).strip()
            gid = (
                str(relationship.group_id).strip()
                if relationship.group_id
                and str(relationship.group_id).strip().lower() != "none"
                else str(RoleType.NORMAL.name).strip().lower()
            )

            if not rid in role_ids:
                role_ids.append(rid)

            if group_roles.get(gid) is None:
                group_roles[gid] = {"type": relationship.type, "role_ids": [rid]}
            else:
                group_roles[gid]["role_ids"].append(rid)

    if len(role_ids):
        roles = {}

        # @TODO: If role_ids more than 100, will be failure.
        for role in RoleModel.scan(RoleModel.role_id.is_in(*list(set(role_ids)))):
            role = Utility.json_loads(
                Utility.json_dumps(role.__dict__["attribute_values"])
            )

            if role.get("permissions") and ignore_permissions:
                del role["permissions"]

            if role.get("role_id") and role.get("name"):
                roles[role.get("role_id")] = {
                    "name": role.get("name"),
                    "id": role.get("role_id"),
                    "type": role.get("type"),
                }

        for gid, value in group_roles.items():
            group_roles[gid] = {
                "group_id": gid,
                "relationship_type": value.get("type"),
                "roles": [
                    roles.get(rid)
                    for rid in list(set(value.get("role_ids")))
                    if roles.get(rid)
                ],
            }

    return group_roles.values()


# Obtain user roles according to the specified user ID
# relationship_type: 0 - team, 1 - seller
def _get_users_by_role_type(role_types, relationship_type=0, group_ids=None) -> list:
    if type(role_types) is not list and len(role_types):
        return []

    role_types = list(set([int(role_type) for role_type in role_types]))

    if type(group_ids) is list and len(group_ids):
        group_ids = list(set([str(group_id).strip() for group_id in group_ids]))

    filter_condition = (
        (RoleModel.is_admin == True)
        & (RoleModel.status == True)
        & (RoleModel.type.is_in(*role_types))
    )
    roles_result_iterator = RoleModel.scan(filter_condition=filter_condition)
    roles = []

    for role in roles_result_iterator:
        item = Utility.json_loads(Utility.json_dumps(role.__dict__["attribute_values"]))
        filter_condition = (RelationshipModel.role_id == role.role_id) & (
            RelationshipModel.type == int(relationship_type)
        )

        if item.get("permissions"):
            del item["permissions"]

        relationships = [
            Utility.json_loads(Utility.json_dumps(user.__dict__["attribute_values"]))
            for user in RelationshipModel.scan(filter_condition=filter_condition)
        ]

        if len(relationships):
            cognito_user_subs = [
                relationship.get("user_id") for relationship in relationships
            ]
            users = {}
            response = {}

            if len(cognito_user_subs):
                method = Utility.import_dynamically(
                    "relation_engine",
                    "get_users_by_cognito_user_id",
                    "RelationEngine",
                    {"logger": None},
                )

                if not callable(method):
                    raise Exception(
                        "Module is not exists or the function is uncallable", 500
                    )

                users = method(cognito_user_subs)

            for relationship in relationships:
                if (
                    type(group_ids) is list
                    and len(group_ids)
                    and relationship.get("group_id")
                    and not str(relationship.get("group_id")).strip() in group_ids
                ):
                    continue

                if relationship.get("user_id") and users.get(
                    relationship.get("user_id")
                ):
                    relationship.update(
                        {"user_base_info": users.get(relationship.get("user_id"))}
                    )

                if relationship.get("group_id"):
                    if not response.get(relationship.get("group_id")):
                        response.update({relationship.get("group_id"): []})

                    response[relationship.get("group_id")].append(relationship)

            item.update({"groups": response})
            roles.append(item)

    return roles


def _get_roles_by_type(types, status=None, is_admin=None) -> dict:
    try:
        roles = {}

        if type(types) is list and len(types):
            types = list(set([int(role_type) for role_type in types]))
            filter_condition = RoleModel.type.is_in(*types)

            if type(status) is bool:
                filter_condition = filter_condition & (RoleModel.status == status)

            if type(is_admin) is bool:
                filter_condition = filter_condition & (RoleModel.is_admin == is_admin)

            for role in RoleModel.scan(filter_condition=filter_condition):
                if type(roles.get(role.type)) is not list:
                    roles[role.type] = []

                roles[role.type].append(role)

        return roles
    except Exception as e:
        raise e


# Delete user roles by conditions.
def _delete_relationships_by_condition(
    relationship_type,
    role_ids=None,
    group_ids=None,
    user_ids=None,
):
    try:
        if role_ids and type(role_ids) is not list:
            role_ids = [str(role_ids).strip()]

        if relationship_type is None:
            raise Exception("Missing required parameters", 400)
        elif (
            (
                type(group_ids) is list
                and len(group_ids) > 99
                and RoleRelationshipType.ADMINISTRATOR.value != relationship_type
            )
            or (type(role_ids) is list and len(role_ids) > 99)
            or (type(user_ids) is list and len(user_ids) > 99)
        ):
            raise Exception(
                "The number of batch query operations must be less than 100", 400
            )

        filter_conditions = [RelationshipModel.type == int(relationship_type)]

        if type(group_ids) is list and len(group_ids):
            group_ids = list(set([str(group_id).strip() for group_id in group_ids]))

            filter_conditions.append(RelationshipModel.group_id.is_in(*group_ids))

        if type(role_ids) is list and len(role_ids):
            role_ids = list(set([str(role_id).strip() for role_id in role_ids]))

            filter_conditions.append(RelationshipModel.role_id.is_in(*role_ids))

        if type(user_ids) is list and len(user_ids):
            user_ids = list(set([str(user_id).strip() for user_id in user_ids]))

            filter_conditions.append(RelationshipModel.user_id.is_in(*user_ids))

        filter_condition = None

        if len(filter_conditions):
            filter_condition = filter_conditions.pop(0)

            for condition in filter_conditions:
                filter_condition = filter_condition & (condition)

        print("DELETE RELATIONSHIP BY CONDITION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        for relationship in RelationshipModel.scan(filter_condition=filter_condition):
            print(relationship)
            relationship.delete()


        return True
    except Exception as e:
        print(type(e), e)
        raise e


# Check user permissions.
def _check_user_permissions(
    module_name,
    class_name,
    function_name,
    operation_type,
    operation,
    relationship_type,
    user_id,
    group_id,
):
    try:
        if (
            not module_name
            or not class_name
            or not function_name
            or not operation
            or not operation_type
            or not user_id
            or not group_id
            or relationship_type is None
        ):
            return False

        get_users = Utility.import_dynamically(
            "relation_engine",
            "get_users_by_cognito_user_id",
            "RelationEngine",
            {"logger": None},
        )

        if not callable(get_users):
            raise Exception("Module is not exists or the function is uncallable", 500)

        users = get_users([str(user_id).strip()])

        if len(users) < 1:
            return False
        elif bool(int(users.get(str(user_id).strip(), {}).get("is_admin", 0))):
            return True

        ### 1. Check user & team relationship exists.
        filter_condition = (
            (RelationshipModel.user_id == str(user_id).strip())
            & (RelationshipModel.group_id == str(group_id).strip())
            & (RelationshipModel.type == int(relationship_type))
        )
        role_ids = list(
            set(
                [
                    relationship.role_id
                    for relationship in RelationshipModel.scan(
                        filter_condition=filter_condition
                    )
                    if relationship.role_id
                ]
            )
        )

        if len(role_ids) < 1:
            return False

        #### 1.1. Get roles by role ids
        # @TODO: len(role_ids) must less than 99
        max_length = 90
        permissions = []

        for i in range(0, len(role_ids), max_length):
            filter_condition = RoleModel.role_id.is_in(*role_ids[i : i + max_length])

            for role in RoleModel.scan(filter_condition=filter_condition):
                if (
                    role.permissions
                    and type(role.permissions) is list
                    and len(role.permissions)
                ):
                    permissions += role.permissions

        if len(permissions) < 1:
            return False

        ### 2. Get resources.
        filter_condition = (
            (ResourceModel.module_name == str(module_name).strip())
            & (ResourceModel.class_name == str(class_name).strip())
            & (ResourceModel.function == str(function_name).strip())
        )
        resource_ids = list(
            set(
                [
                    str(resource.resource_id).strip()
                    for resource in ResourceModel.scan(
                        filter_condition=filter_condition
                    )
                    if resource.resource_id
                ]
            )
        )

        if len(resource_ids) < 1:
            return False

        operation_type = str(operation_type).strip()
        operation = str(operation).strip()

        for permission in permissions:
            if (
                not permission.resource_id
                or type(permission.permissions) is not list
                or len(permission.permissions) < 1
            ):
                continue

            if str(permission.resource_id).strip() in resource_ids:
                for p in permission.permissions:
                    if p.operation == operation_type and p.operation_name == operation:
                        return True

        return False
    except Exception as e:
        raise e


def add_resource():
    with open("f:\install.log", "a") as fd:
        print("mtest")
        fd.write("Test\n")
