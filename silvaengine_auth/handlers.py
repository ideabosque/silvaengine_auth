from re import T
import uuid, json, time, urllib.request, os
from datetime import datetime
from graphene.types import field
from jose import jwk, jwt
from jose.utils import base64url_decode
from jose.constants import ALGORITHMS
from hashlib import md5
from importlib.util import find_spec
from importlib import import_module
from pynamodb.expressions.condition import Condition
from silvaengine_utility import Utility, Graphql, Authorizer
from silvaengine_resource import ResourceModel
from .utils import validate_required, get_seller_id, is_admin_user
from .models import ConnectionModel, RelationshipModel, RoleModel, ConfigDataModel


def _create_role_handler(info, role_input):
    try:
        role_id = str(uuid.uuid1())
        # owner_id = role_input.owner_id if role_input.owner_id is not None else ""
        owner_id = get_seller_id(info.context)
        now = datetime.utcnow()
        status = bool(role_input.status)

        RoleModel(
            role_id,
            **{
                "name": role_input.name,
                "owner_id": owner_id,
                "is_admin": is_admin_user(info.context),
                "description": role_input.description,
                "permissions": role_input.permissions,
                "created_at": now,
                "updated_at": now,
                "updated_by": role_input.updated_by,
                "status": status,
            },
        ).save()

        return RoleModel.get(role_id, None)
    except Exception as e:
        raise e


def _update_role_handler(info, role_input):
    try:
        validate_required(["role_id"], role_input)

        role = RoleModel(role_input.role_id)
        actions = [
            RoleModel.updated_at.set(datetime.utcnow()),
        ]
        fields = [
            "name",
            "updated_by",
            # "owner_id",
            "is_admin",
            "description",
            "permissions",
            "status",
        ]
        owner_id = get_seller_id(info)
        condition = (RoleModel.role_id == role_input.role_id) & (
            RoleModel.owner_id == owner_id
        )

        if owner_id is None:
            condition = (RoleModel.role_id == role_input.role_id) & (
                RoleModel.owner_id.does_not_exist()
            )

        need_update = False

        for field in fields:
            if hasattr(role_input, field) and getattr(role_input, field):
                need_update = True

                actions.append(
                    getattr(RoleModel, field).set(getattr(role_input, field))
                )

        if need_update:
            role.update(
                actions=actions,
                condition=condition,
            )

        return RoleModel.get(role_input.role_id, None)
    except Exception as e:
        raise e


def _delete_role_handler(info, role_input):
    try:
        validate_required(["role_id"], role_input)
        owner_id = get_seller_id(info)
        condition = (RoleModel.role_id == role_input.role_id) & (
            RoleModel.owner_id == owner_id
        )

        if owner_id is None:
            condition = (RoleModel.role_id == role_input.role_id) & (
                RoleModel.owner_id.does_not_exist()
            )

        # Delete the role record.
        return RoleModel(role_input.role_id).delete(condition=condition)
    except Exception as e:
        raise e


def _create_relationship_handler(info, input):
    try:
        validate_required(["group_id", "user_id", "role_id"], input)

        relationship_id = str(uuid.uuid1())

        RelationshipModel(
            relationship_id,
            **{
                "user_id": input.user_id,
                "role_id": input.role_id,
                "group_id": input.group_id,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "updated_by": input.updated_by,
                "status": bool(input.status),
            },
        ).save()

        # relationship_id = "a6bd834c-fa75-11eb-8633-0242ac120002"
        # conditions = RelationshipModel.group_id.does_not_exist()
        # relationships = RelationshipModel.scan(conditions)

        # for r in relationships:
        #     print(r.group_id, r.role_id)

        return RelationshipModel.get(relationship_id)
    except Exception as e:
        raise e


def _update_relationship_handler(info, input):
    try:
        validate_required(["relationship_id"], input)

        relationship = RelationshipModel(input.relationship_id)
        actions = [
            RelationshipModel.updated_at.set(datetime.utcnow()),
        ]
        fields = [
            "user_id",
            "role_id",
            "group_id",
            "is_admin",
            "updated_by",
            "status",
        ]
        need_update = False

        for field in fields:
            if hasattr(input, field) and getattr(input, field):
                need_update = True

                actions.append(
                    getattr(RelationshipModel, field).set(getattr(input, field))
                )

        if need_update:
            relationship.update(
                actions=actions,
                condition=RelationshipModel.relationship_id == input.relationship_id,
            )

        return RelationshipModel.get(input.relationship_id)
    except Exception as e:
        raise e


def _delete_relationship_handler(info, input):
    try:
        validate_required(["relationship_id"], input)

        # Delete the group/user/role relationship.
        return RelationshipModel(input.relationship_id).delete()
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
            not event.get("fnConfigurations").get("config").get("auth_required")
            or event.get("requestContext")
            .get("authorizer")
            .get("is_allowed_by_whitelist")
            == "1"
        ):
            return event

        if (
            not event.get("pathParameters").get("proxy")
            or not event.get("headers")
            or not event.get("body")
            or not event.get("fnConfigurations")
            or not event.get("requestContext").get("authorizer").get("sub")
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
        uid = authorizer.get("sub")
        owner_id = (
            str(authorizer.get("seller_id")).strip()
            if authorizer.get("seller_id") is not None
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

        filter_conditions = RoleModel.owner_id == str(owner_id)

        if is_admin or owner_id is None or owner_id == "":
            filter_conditions = RoleModel.owner_id.does_not_exist()

        roles = [
            role
            for role in RoleModel.scan(
                RoleModel.role_id.is_in(*role_ids) & filter_conditions
            )
        ]

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
            ) or not check_permission(roles, item):
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
        api_id = event.get("requestContext").get("apiId")
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
            ctx["seller_id"] = str(headers.get("seller_id")).strip()

        if headers.get("team_id"):
            ctx["team_id"] = str(headers.get("team_id")).strip()

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

            if bool(int(additional_context.get("is_admin").strip())) == False:
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

        # Append the custom context hooks setting to context
        if settings.get("custom_context_hooks"):
            additional_context.update(
                {"custom_context_hooks": settings.get("custom_context_hooks")}
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
        rules = []
        is_admin = (
            bool(int(authorizer.get("is_admin")))
            if authorizer.get("is_admin")
            else False
        )
        cognito_user_sub = authorizer.get("sub")

        if not cognito_user_sub:
            return rules

        # Query user / group / role relationships
        role_ids = [
            relationship.role_id
            for relationship in RelationshipModel.scan(
                RelationshipModel.user_id == cognito_user_sub
            )
        ]

        if len(role_ids) < 1:
            return rules

        owner_id = authorizer.get("seller_id")
        filter_conditions = RoleModel.owner_id == str(owner_id)

        if is_admin or owner_id is None or owner_id == "":
            filter_conditions = RoleModel.owner_id.does_not_exist()

        for role in RoleModel.scan(
            RoleModel.role_id.is_in(*role_ids) & filter_conditions
        ):
            rules += role.permissions

        resources = {}
        resource_ids = list(set([str(rule.resource_id).strip() for rule in rules]))

        if len(resource_ids) < 1:
            return None

        for resource in ResourceModel.scan(
            ResourceModel.resource_id.is_in(*resource_ids)
        ):
            resources[resource.resource_id] = resource

        result = {}

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


def check_permission(roles, resource) -> bool:
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


def convert_permisson_as_dict(permissions):
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


def add_resource():
    with open("f:\install.log", "a") as fd:
        print("mtest")
        fd.write("Test\n")
