#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

import os
from pynamodb.models import Model
from pynamodb.attributes import (
    ListAttribute,
    MapAttribute,
    UnicodeAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    NumberAttribute,
)


class BaseModel(Model):
    class Meta:
        billing_mode = "PAY_PER_REQUEST"
        region = os.getenv("REGIONNAME")
        aws_access_key_id = os.getenv("aws_access_key_id")
        aws_secret_access_key = os.getenv("aws_secret_access_key")

        if region is None or aws_access_key_id is None or aws_secret_access_key is None:
            from dotenv import load_dotenv

            if load_dotenv():
                if region is None:
                    region = os.getenv("region_name")

                if aws_access_key_id is None:
                    aws_access_key_id = os.getenv("aws_access_key_id")

                if aws_secret_access_key is None:
                    aws_secret_access_key = os.getenv("aws_secret_access_key")


class TraitModel(BaseModel):
    class Meta(BaseModel.Meta):
        pass

    created_at = UTCDateTimeAttribute()
    updated_at = UTCDateTimeAttribute()
    updated_by = UnicodeAttribute()


class RoleModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-roles"

    role_id = UnicodeAttribute(hash_key=True)
    owner_id = UnicodeAttribute(default="0")
    name = UnicodeAttribute()
    permissions = ListAttribute(of=MapAttribute)
    description = UnicodeAttribute()
    is_admin = BooleanAttribute()
    user_ids = ListAttribute()
    status = BooleanAttribute(default=True)


class RelationshipModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-relationships"

    group_id = UnicodeAttribute(hash_key=True)
    user_id = UnicodeAttribute(range_key=True)
    role_id = UnicodeAttribute()
    # permissions = ListAttribute(of=MapAttribute)
    # description = UnicodeAttribute()
    # is_admin = BooleanAttribute()
    # user_ids = ListAttribute()
    # status = BooleanAttribute(default=True)


class ConfigDataModel(BaseModel):
    class Meta(BaseModel.Meta):
        table_name = "se-configdata"

    setting_id = UnicodeAttribute(hash_key=True)
    variable = UnicodeAttribute(range_key=True)
    value = UnicodeAttribute()


class FunctionMap(MapAttribute):
    aws_lambda_arn = UnicodeAttribute()
    function = UnicodeAttribute()
    setting = UnicodeAttribute()


class ConnectionModel(BaseModel):
    class Meta(BaseModel.Meta):
        table_name = "se-connections"

    endpoint_id = UnicodeAttribute(hash_key=True)
    api_key = UnicodeAttribute(range_key=True, default="#####")
    functions = ListAttribute(of=FunctionMap)
    whitelist = ListAttribute()
