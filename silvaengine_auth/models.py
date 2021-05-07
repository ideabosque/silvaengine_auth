#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from pynamodb.models import Model
from pynamodb.attributes import (
    ListAttribute,
    MapAttribute,
    UnicodeAttribute,
    UnicodeSetAttribute,
    UTCDateTimeAttribute,
    NumberAttribute,
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


class ResourceModel(AuthBaseModel):
    class Meta(AuthBaseModel.Meta):
        table_name = "se-resources"

    resource_id = UnicodeAttribute(hash_key=True)
    service = UnicodeAttribute(range_key=True)
    path = UnicodeAttribute()
    name = UnicodeAttribute()
    status = NumberAttribute()
    # action = UnicodeAttribute()


class RoleModel(AuthBaseModel):
    class Meta(AuthBaseModel.Meta):
        table_name = "se-roles"

    role_id = UnicodeAttribute(hash_key=True)
    name = UnicodeAttribute()
    permissions = ListAttribute(of=MapAttribute)
    user_ids = ListAttribute()
