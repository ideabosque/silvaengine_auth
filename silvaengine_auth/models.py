#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from enum import Enum
from pynamodb.models import Model
from pynamodb.attributes import (
    ListAttribute,
    MapAttribute,
    UnicodeAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    NumberAttribute,
)
import os

__author__ = "bl"


class RoleType(Enum):
    NORMAL = 0
    ACCOUNT_MANAGER = 1
    QC_MANAGER = 2
    DEPT_MANAGER = 3


class RoleRelationshipType(Enum):
    ADMINISTRATOR = 0
    SELLER = 1
    COMPANY = 2
    FACTORY = 3
    PRE_ASSIGN_SELLER = 4


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


class ResourceConstraintMap(MapAttribute):
    operation = UnicodeAttribute()
    operation_name = UnicodeAttribute()
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = ListAttribute()
    # field = String()


class RoleConstraintMap(MapAttribute):
    resource_id = UnicodeAttribute()
    permissions = ListAttribute(of=ResourceConstraintMap)


class RoleModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-roles"

    role_id = UnicodeAttribute(hash_key=True)
    # type: 0 - Normal, 1 - GWI Account Manger, 2 - GWI QC Manager
    type = NumberAttribute(default=0)
    name = UnicodeAttribute()
    permissions = ListAttribute(of=RoleConstraintMap)
    description = UnicodeAttribute(null=True)
    is_admin = BooleanAttribute(default=False)
    status = BooleanAttribute(default=True)


class RelationshipModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-relationships"

    relationship_id = UnicodeAttribute(hash_key=True)
    # type: 0 - amdin, 1 - Seller, 2 - team
    type = NumberAttribute(default=0)
    user_id = UnicodeAttribute()
    role_id = UnicodeAttribute()
    group_id = UnicodeAttribute(null=True)
    status = BooleanAttribute(default=True)


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
