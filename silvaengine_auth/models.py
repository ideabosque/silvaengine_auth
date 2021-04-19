#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from pynamodb.models import Model
from pynamodb.attributes import (
    ListAttribute,
    UnicodeAttribute,
    UnicodeSetAttribute,
    UTCDateTimeAttribute,
)


class BaseModel(Model):
    class Meta:
        billing_mode = "PAY_PER_REQUEST"


class AuthBaseModel(BaseModel):
    class Meta(BaseModel.Meta):
        pass

    created_at = UTCDateTimeAttribute()
    updated_at = UTCDateTimeAttribute()
    updated_by = UnicodeAttribute()


class PermissionsModel(AuthBaseModel):
    class Meta(AuthBaseModel.Meta):
        table_name = "se-permissions"

    permission_id = UnicodeAttribute(hash_key=True)
    service = UnicodeAttribute(range_key=True)
    action = UnicodeAttribute()
    paths = ListAttribute()


class RolesModel(AuthBaseModel):
    class Meta(AuthBaseModel.Meta):
        table_name = "se-roles"

    role_id = UnicodeAttribute(hash_key=True)
    name = UnicodeAttribute()
    permission_ids = ListAttribute()
    user_ids = ListAttribute()