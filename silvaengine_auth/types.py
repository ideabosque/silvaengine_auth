#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

from graphene import (
    ObjectType,
    InputObjectType,
    String,
    Decimal,
    DateTime,
    List,
    Field,
    Int,
)


class PermissionType(ObjectType):
    resource_id = String()
    permission = Int()


class PermissionInputType(InputObjectType):
    resource_id = String()
    permission = Int()


class ResourceType(ObjectType):
    resource_id = String()
    service = String()
    path = String()
    name = String()
    status = Int()
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    last_evaluated_key = String()


class RoleType(ObjectType):
    role_id = String()
    name = String()
    permissions = List(PermissionType)
    user_ids = List(String)
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    last_evaluated_key = String()


class ResourceInputType(InputObjectType):
    resource_id = String()
    service = String()
    path = String()
    name = String()
    status = Int()
    updated_by = String()


class RoleInputType(InputObjectType):
    role_id = String()
    name = String()
    permissions = List(PermissionInputType)
    user_ids = List(String)
    updated_by = String()
