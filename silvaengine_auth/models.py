#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import os
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
        region = os.getenv("REGIONNAME")

        if not region:
            region = os.getenv("region_name")
            aws_access_key_id = os.getenv("aws_access_key_id")
            aws_secret_access_key = os.getenv("aws_secret_access_key")


class TraitModel(BaseModel):
    class Meta(BaseModel.Meta):
        pass

    created_at = UTCDateTimeAttribute()
    updated_at = UTCDateTimeAttribute()
    updated_by = UnicodeAttribute()


class ResourceModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-resources"

    resource_id = UnicodeAttribute(hash_key=True)
    service = UnicodeAttribute(range_key=True)
    path = UnicodeAttribute()
    name = UnicodeAttribute()
    status = NumberAttribute()
    # action = UnicodeAttribute()


class RoleModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-roles"

    role_id = UnicodeAttribute(hash_key=True)
    name = UnicodeAttribute()
    permissions = ListAttribute(of=MapAttribute)
    user_ids = ListAttribute()
