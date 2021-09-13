#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from graphene import ObjectType, String, Int, Schema, Field, Boolean, List
from silvaengine_utility import JSON
from .types import (
    RelationshipInputType,
    RoleType,
    RolesType,
    CertificateType,
    RelationshipsType,
    UserRelationshipsType,
)
from .queries import (
    _resolve_roles,
    _resolve_role,
    _resolve_certificate,
    _resolve_users,
)
from .mutations import (
    CreateRole,
    UpdateRole,
    DeleteRole,
    CreateRelationship,
    UpdateRelationship,
    DeleteRelationship,
    SaveRelationships,
)

__author__ = "bl"


def role_type_class():
    return [
        RolesType,
        RoleType,
        RelationshipsType,
        UserRelationshipsType,
    ]


def certificate_type_class():
    return [CertificateType]


# Query for user login
class CertificateQuery(ObjectType):
    certificate = Field(
        CertificateType,
        username=String(required=True),
        password=String(required=True),
    )

    def resolve_certificate(self, info, **kwargs):
        return _resolve_certificate(info, **kwargs)


# Query role list or role
class RoleQuery(ObjectType):
    roles = Field(
        RolesType,
        page_size=Int(),
        page_number=Int(),
        is_admin=Boolean(),
        name=String(),
        role_description=String(),
        role_type=Int(),
        user_ids=List(String),
        status=Boolean()
        # last_evaluated_key=JSON(),
    )

    role = Field(
        RoleType,
        role_id=String(required=True),
    )

    users = Field(
        UserRelationshipsType,
        page_size=Int(),
        page_number=Int(),
        status=Boolean(),
        role_id=String(),
        role_name=String(),
        is_admin=Boolean(),
        role_type=Int(),
        group_id=String(),
        # last_evaluated_key=JSON(),
    )

    def resolve_roles(self, info, **kwargs):
        return _resolve_roles(info, **kwargs)

    def resolve_role(self, info, **kwargs):
        return _resolve_role(info, **kwargs)

    def resolve_users(self, info, **kwargs):
        return _resolve_users(info, **kwargs)


# Modify role / relation list or role / relation
class RoleMutations(ObjectType):
    create_role = CreateRole.Field()
    update_role = UpdateRole.Field()
    delete_role = DeleteRole.Field()
    create_relationship = CreateRelationship.Field()
    update_relationship = UpdateRelationship.Field()
    delete_relationship = DeleteRelationship.Field()
    save_relationships = SaveRelationships.Field()


# Generate API documents.
def graphql_schema_doc():
    from graphdoc import to_doc

    schema = Schema(
        query=RoleQuery,
        mutation=RoleMutations,
        types=role_type_class(),
    )

    return to_doc(schema)
