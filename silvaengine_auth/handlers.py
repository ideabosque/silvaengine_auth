import uuid, json, time, urllib.request, os
from datetime import datetime
from jose import jwk, jwt
from jose.utils import base64url_decode
from jose.constants import ALGORITHMS
from hashlib import md5
from importlib.util import find_spec
from importlib import import_module
from pynamodb.expressions.condition import Condition
from silvaengine_utility import Utility
from silvaengine_resource import ResourceModel
from .utils import extract_fields_from_ast, HttpVerb, AuthPolicy, validate_required
from .models import ConnectionModel, RelationshipModel, RoleModel, ConfigDataModel


def _create_role_handler(info, role_input):
    try:
        role_id = str(uuid.uuid1())
        owner_id = role_input.owner_id if role_input.owner_id is not None else ""
        now = datetime.utcnow()
        status = bool(role_input.status)

        RoleModel(
            role_id,
            **{
                "name": role_input.name,
                "owner_id": owner_id,
                "is_admin": role_input.is_admin,
                "description": role_input.description,
                "permissions": role_input.permissions,
                "user_ids": role_input.user_ids,
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

        role = RoleModel.get(role_input.role_id, None)

        role.update(
            actions=[
                RoleModel.updated_at.set(datetime.utcnow()),
                RoleModel.updated_by.set(role_input.updated_by),
                RoleModel.name.set(role_input.name),
                RoleModel.owner_id.set(role_input.owner_id),
                RoleModel.is_admin.set(role_input.is_admin),
                RoleModel.description.set(role_input.description),
                RoleModel.permissions.set(role_input.permissions),
                RoleModel.user_ids.set(role_input.user_ids),
                RoleModel.status.set(role_input.status),
            ]
        )
        return RoleModel.get(role_input.role_id, None)
    except Exception as e:
        raise e


def _delete_role_handler(info, role_input):
    try:
        validate_required(["role_id"], role_input)

        # Delete the role record.
        return RoleModel(role_input.role_id).delete()
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

        relationship = RelationshipModel.get(input.relationship_id)

        relationship.update(
            actions=[
                RelationshipModel.user_id.set(input.user_id),
                RelationshipModel.role_id.set(input.role_id),
                RelationshipModel.group_id.set(input.group_id),
                RelationshipModel.status.set(input.status),
                RelationshipModel.updated_at.set(datetime.utcnow()),
                RelationshipModel.updated_by.set(input.updated_by),
            ]
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

        # Parse the graphql request's body to AST and extract fields from the AST
        # extract_fields_from_ast(schema, operation, deepth)
        # operation = [mutation | query]
        # create - 1, read - 2, update - 4, delete - 8 crud
        if not function_config.get("config").get("operations"):
            raise Exception(message, 403)

        operations = function_config.get("config").get("operations")
        permission = 0
        fields = extract_fields_from_ast(body, deepth=1)

        if "mutation" in fields:
            # create - 1, query - 2, update = 4, delete = 8
            for operation in operations:
                functions = operations[operation]

                if type(functions) is not list or len(functions) < 1:
                    continue

                for fn in functions:
                    if fn.strip().lower() in fields.get("mutation"):
                        if operation.lower() == "create":
                            permission += 1
                        elif operation.lower() == "update":
                            permission += 4
                        elif operation.lower() == "delete":
                            permission += 8
        elif "query" in fields:  # @TODO: Check query fields permission
            if (
                type(operations.get("query")) is list
                and len(operations.get("query")) > 0
            ):
                for fn in operations.get("query"):
                    if fn.strip().lower() in fields.get("query"):
                        permission += 2
            else:
                permission += 2

        if (
            not permission
            or not function_config.get("config").get("module_name")
            or not function_config.get("config").get("class_name")
        ):
            raise Exception(message, 403)

        # 1. Fetch resource by request path
        # TODO: Use index query to instead of the scan
        factor = "{}-{}-{}".format(
            function_config.get("config").get("module_name").strip(),
            function_config.get("config").get("class_name").strip(),
            function_name,
        ).lower()
        resource_id = md5(factor.encode(encoding="UTF-8")).hexdigest()

        # Check the path of request is be contained  by the permissions of role
        # If the path has exist, compare their permission
        def check_permission(roles, permission) -> bool:
            for role in roles:
                if role and len(role.permissions) > 0:
                    for rule in role.permissions:
                        if (
                            rule.get("resource_id") == resource_id
                            and int(rule.get("permission")) & permission
                        ):
                            return True
            return False

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

        if uid and check_permission(roles, permission):
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
        policy = AuthPolicy(principal, aws_account_id)
        policy.restApiId = api_id
        policy.region = region
        policy.stage = stage

        def response(policy, is_allow=True, context=None):
            # policy.allowAllMethods()
            getattr(policy, "allowAllMethods" if is_allow else "denyAllMethods")()

            # if is_allow:
            # policy.allowMethod(request_method, uri)

            # else:
            #     policy.denyMethod(request_method, uri)
            # """policy.allowMethod(HttpVerb.GET, "/pets/*")"""

            # Finally, build the policy
            authResponse = policy.build()

            # new! -- add additional key-value pairs associated with the authenticated principal
            # these are made available by APIGW like so: $context.authorizer.<key>
            # additional context is cached
            # context = {
            #     "user_id": "test_123456",  # $context.authorizer.key -> value
            #     "number": 1,
            #     "bool": True,
            # }
            # # context['arr'] = ['foo'] <- this is invalid, APIGW will not accept it
            # # context['obj'] = {'foo':'bar'} <- also invalid

            if context:
                authResponse["context"] = context

            return authResponse

        ### 1. Verify source ip
        if _verify_whitelist(event, context):
            custom_context = {"is_allowed_by_whitelist": 1}

            return response(policy=policy, is_allow=True, context=custom_context)

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
            additional_context = {}
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

        return response(policy=policy, context=additional_context)
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

        permissions = {}
        resources = {}
        resource_ids = list(
            set([str(rule.get("resource_id")).strip() for rule in rules])
        )

        if len(resource_ids) < 1:
            return None

        for resource in ResourceModel.scan(
            ResourceModel.resource_id.is_in(*resource_ids)
        ):
            resources[resource.resource_id] = resource

        result = {}

        for rule in rules:
            resource_id = rule.get("resource_id")
            resource = resources.get(resource_id)

            if (
                not resource_id
                or not hasattr(resource, "function")
                or not hasattr(resource, "operations")
            ):
                continue

            function_name = getattr(resource, "function")
            operations = getattr(resource, "operations")

            if not permissions.get(resource_id):
                permissions[resource_id] = 0

            if not result.get(function_name):
                result[function_name] = []

            if rule.get("permission"):
                for permission in [1, 2, 4, 8]:
                    if (permission & int(rule.get("permission"))) and not (
                        permission & permissions[resource_id]
                    ):
                        permissions[resource_id] += permission
                        action = None

                        if permission == 1:
                            action = "create"
                        elif permission == 2:
                            action = "query"
                        elif permission == 4:
                            action = "update"
                        elif permission == 8:
                            action = "delete"

                        if not action or not hasattr(operations, action):
                            continue

                        items = getattr(operations, action)

                        if type(items) is not list or len(items) < 1:
                            continue

                        for item in items:
                            if not getattr(item, "action"):
                                continue

                            result[function_name].append(getattr(item, "action"))
        return result
    except Exception as e:
        raise e


def add_resource():
    with open("f:\install.log", "a") as fd:
        print("mtest")
        fd.write("Test\n")
