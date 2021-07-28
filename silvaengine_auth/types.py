#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from graphene.types.dynamic import Dynamic

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


class LastEvaluatedKey(ObjectType):
    hash_key = String()
    range_key = String()


class PageInputType(InputObjectType):
    hash_key = String()
    range_key = String()


class PermissionType(ObjectType):
    resource_id = String()
    permission = Int()


class PermissionInputType(InputObjectType):
    resource_id = String()
    permission = Int()


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
    last_evaluated_key = Field(LastEvaluatedKey)


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
