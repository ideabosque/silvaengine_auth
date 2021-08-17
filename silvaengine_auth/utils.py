#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"


def validate_required(fields, input):
    try:
        fields = list(set(list(fields)))

        if len(fields) and not input:
            raise Exception("Missing required parameter(s)", 400)

        for field in fields:
            if input and input.get(field) is None:
                raise Exception(f"Parameter `{field}` is required", 400)
    except Exception as e:
        raise e
