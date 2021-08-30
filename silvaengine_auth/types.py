#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from graphene.types.dynamic import Dynamic
from sqlalchemy.orm import relationship
from silvaengine_utility import JSON

__author__ = "bl"

from graphene import (
    ObjectType,
    InputObjectType,
    String,
    DateTime,
    List,
    Int,
    Field,
    Boolean,
)
from silvaengine_utility import JSON


class ConstraintType(ObjectType):
    operation = String(required=True)
    operation_name = String(required=True)
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = List(String)
    # field = String()


class ConstraintInputType(InputObjectType):
    operation = String(required=True)
    operation_name = String(required=True)
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = List(String)
    # field = String()


class PermissionType(ObjectType):
    resource_id = String()
    permissions = List(ConstraintType)


class PermissionInputType(InputObjectType):
    resource_id = String()
    permissions = List(ConstraintInputType)


class RoleType(ObjectType):
    role_id = String()
    name = String()
    owner_id = String()
    description = String()
    permissions = List(PermissionType)
    is_admin = Boolean()
    user_ids = List(String)
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    status = Boolean()


class RolesType(ObjectType):
    items = List(RoleType)
    last_evaluated_key = JSON()


class RelationshipType(ObjectType):
    relationship_id = String()
    group_id = String()
    user_id = String()
    role_id = String()
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    status = Boolean()


class UserRelationshipType(ObjectType):
    relationship_id = String()
    group_id = String()
    user_id = String()
    user = JSON()
    role_id = String()
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    status = Boolean()


class RelationshipsType(ObjectType):
    items = List(RelationshipType)
    last_evaluated_key = JSON()


class UserRelationshipsType(ObjectType):
    items = List(UserRelationshipType)
    last_evaluated_key = JSON()


class RoleInputType(InputObjectType):
    role_id = String()
    owner_id = String()
    name = String()
    description = String()
    is_admin = Boolean()
    permissions = List(PermissionInputType)
    user_ids = List(String)
    updated_by = String()
    status = Boolean()


class CertificateType(ObjectType):
    access_token = String()
    id_token = String()
    refresh_token = String()
    expires_in = Int()
    token_type = String()
    permissions = JSON()
    context = JSON()


class RelationshipInputType(InputObjectType):
    relationship_id = String()
    group_id = String()
    user_id = String()
    role_id = String()
    updated_by = String()
    status = Boolean()
