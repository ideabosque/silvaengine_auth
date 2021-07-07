#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from graphene.types.scalars import Boolean

__author__ = "bl"

from graphene import ObjectType, InputObjectType, String, DateTime, List, Int, Field


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
    description = String()
    permissions = List(PermissionType)
    is_admin = Boolean()
    user_ids = List(String)
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()


class RolesType(ObjectType):
    items = List(RoleType)
    last_evaluated_key = Field(LastEvaluatedKey)


class RoleInputType(InputObjectType):
    role_id = String()
    name = String()
    description = String()
    is_admin = Boolean()
    permissions = List(PermissionInputType)
    user_ids = List(String)
    updated_by = String()
