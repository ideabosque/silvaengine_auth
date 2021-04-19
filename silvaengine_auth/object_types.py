#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from graphene import ObjectType, InputObjectType, String, Decimal, DateTime, List, Field


class PermissionType(ObjectType):
    permission_id = String()
    service = String()
    action = String()
    paths = List(String)
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    last_evaluated_key = String()


class RoleType(ObjectType):
    role_id = String()
    name = String()
    permission_ids = List(String)
    user_ids = List(String)
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    last_evaluated_key = String()


class PermissionInputType(InputObjectType):
    permission_id = String()
    service = String()
    action = String()
    paths = List(String)
    updated_by = String()


class RoleInputType(InputObjectType):
    role_id = String()
    name = String()
    permission_ids = List(String)
    user_ids = List(String)
    updated_by = String()