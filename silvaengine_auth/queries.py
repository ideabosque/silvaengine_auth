import boto3, os, hmac, hashlib, base64
from importlib.util import find_spec
from importlib import import_module
from silvaengine_utility import Utility
from jose import jwk, jwt
from .types import (
    RelationshipType,
    RoleType,
    RolesType,
    CertificateType,
    UserRelationshipType,
    UserRelationshipsType,
)
from .models import RelationshipModel, RoleModel
from .handlers import _get_user_permissions


# @TODO: Apply status check
def _resolve_roles(info, **kwargs):
    try:
        limit = kwargs.get("limit")
        last_evaluated_key = kwargs.get("last_evaluated_key")
        filter_conditions = None

        if kwargs.get("owner_id"):
            if str(kwargs.get("owner_id")).strip() == "":
                filter_conditions = RoleModel.owner_id.does_not_exist()
            else:
                filter_conditions = (
                    RoleModel.owner_id == str(kwargs.get("owner_id")).strip()
                )

        if last_evaluated_key:
            last_evaluated_key = Utility.json_loads(
                Utility.json_dumps(last_evaluated_key)
            )

        results = RoleModel.scan(
            filter_condition=filter_conditions,
            limit=int(limit),
            last_evaluated_key=last_evaluated_key,
        )

        roles = [
            RoleType(
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
            last_evaluated_key=Utility.json_loads(
                Utility.json_dumps(results.last_evaluated_key)
            ),
        )
    except Exception as e:
        raise e


# @TODO: Apply status check
def _resolve_users(info, **kwargs):
    try:
        limit = kwargs.get("limit")
        last_evaluated_key = kwargs.get("last_evaluated_key")
        filter_conditions = RoleModel.owner_id == str(kwargs.get("owner_id")).strip()

        # owner id
        if str(kwargs.get("owner_id")).strip() == "":
            filter_conditions = RoleModel.owner_id.does_not_exist()

        # Query role IDs by owner id
        role_ids = [
            str(role.role_id).strip()
            for role in RoleModel.scan(filter_condition=filter_conditions)
        ]

        if len(role_ids) < 1:
            raise Exception(
                "There are currently no roles available for the seller", 406
            )

        filter_conditions = RelationshipModel.role_id.is_in(*role_ids)

        # If the role IDs don't include the role id which pass by top layer
        if kwargs.get("role_id"):
            if str(kwargs.get("role_id")).strip() not in role_ids:
                raise Exception(
                    "The specified role does not belong to the specified owner", 400
                )

            filter_conditions = (
                RelationshipModel.role_id == str(kwargs.get("role_id")).strip()
            )

        if last_evaluated_key:
            last_evaluated_key = Utility.json_loads(
                Utility.json_dumps(last_evaluated_key)
            )

        if str(kwargs.get("group_id", "")).strip() != "":
            filter_conditions = filter_conditions & (
                RelationshipModel.group_id == str(kwargs.get("group_id")).strip()
            )

        results = RelationshipModel.scan(
            filter_condition=filter_conditions,
            limit=int(limit),
            last_evaluated_key=last_evaluated_key,
        )
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

        if len(relationships) < 1:
            raise Exception("No matching data found", 406)

        hooks = (
            [
                hook.strip()
                for hook in info.context.get("setting").get("custom_hooks").split(",")
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
                users = Utility.import_dynamically(
                    module_name, function_name, class_name, {"logger": logger}
                )([relationship.user_id for relationship in relationships])
                items = []

                if len(users):
                    for relationship in relationships:
                        if relationship.user_id and users.get(relationship.user_id):
                            relationship.user = users.get(relationship.user_id)

                        items.append(relationship)

                relationships = items

        if results.total_count < 1:
            return None

        return UserRelationshipsType(
            items=relationships,
            last_evaluated_key=Utility.json_loads(
                Utility.json_dumps(results.last_evaluated_key)
            ),
        )
    except Exception as e:
        raise e


def _resolve_role(info, **kwargs):
    role_id = kwargs.get("role_id")

    if role_id:
        role = RoleModel.get(role_id)

        return RoleType(
            **Utility.json_loads(Utility.json_dumps(role.__dict__["attribute_values"]))
        )

    return None


def _resolve_certificate(info, **kwargs):
    try:
        username = kwargs.get("username")
        password = kwargs.get("password")

        assert username or password, "Username or password is required"

        region_name = (
            info.context.get("setting").get("region_name")
            if info.context.get("setting").get("region_name")
            else os.getenv("REGIONNAME")
        )
        aws_access_key_id = (
            info.context.get("setting").get("aws_access_key_id")
            if info.context.get("setting").get("aws_access_key_id")
            else os.getenv("aws_access_key_id")
        )
        aws_secret_access_key = (
            info.context.get("setting").get("aws_secret_access_key")
            if info.context.get("setting").get("aws_secret_access_key")
            else os.getenv("aws_secret_access_key")
        )
        app_client_id = (
            info.context.get("setting").get("app_client_id")
            if info.context.get("setting").get("app_client_id")
            else os.getenv("app_client_id")
        )
        app_client_secret = (
            info.context.get("setting").get("app_client_secret")
            if info.context.get("setting").get("app_client_secret")
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

        if not response.get("AuthenticationResult").get("IdToken"):
            raise Exception("Failed to sign in on cognito")

        # @TODO: hooks
        hooks = (
            [
                hook.strip()
                for hook in info.context.get("setting")
                .get("custom_signin_hooks")
                .split(",")
            ]
            if info.context.get("setting").get("custom_signin_hooks")
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
