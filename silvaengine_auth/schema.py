#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

from graphene import ObjectType, String, Int, Schema, Field
from .types import RoleType, RolesType, PageInputType, CertificateType
from .queries import _resolve_roles, _resolve_role, _resolve_certificate
from .mutations import CreateRole, UpdateRole, DeleteRole


def role_type_class():
    return [RolesType, RoleType]


def certificate_type_class():
    return [CertificateType]


# Query for user login
class CertificateQuery(ObjectType):
    certificate = Field(
        CertificateType,
        username=String(),
        password=String(),
    )

    def resolve_certificate(self, info, **kwargs):
        return _resolve_certificate(info, **kwargs)


# Query role list or role
class RoleQuery(ObjectType):
    roles = Field(
        RolesType,
        limit=Int(),
        last_evaluated_key=PageInputType(),
    )

    role = Field(
        RoleType,
        role_id=String(),
    )

    def resolve_roles(self, info, **kwargs):
        return _resolve_roles(info, **kwargs)

    def resolve_role(self, info, **kwargs):
        return _resolve_role(info, **kwargs)


# Modify role list or role
class RoleMutations(ObjectType):
    create_role = CreateRole.Field()
    update_role = UpdateRole.Field()
    delete_role = DeleteRole.Field()


# Generate API documents.
def graphql_schema_doc():
    from graphdoc import to_doc

    schema = Schema(
        query=RoleQuery,
        mutation=RoleMutations,
        types=role_type_class(),
    )

    return to_doc(schema)
