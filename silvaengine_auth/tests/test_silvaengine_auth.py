#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import logging, sys, json, unittest, uuid, os
from datetime import datetime, timedelta, date
from decimal import Decimal
from pathlib import Path
from silvaengine_utility import Utility

from dotenv import load_dotenv

load_dotenv()
setting = {
    "region_name": os.getenv("region_name"),
    "aws_access_key_id": os.getenv("aws_access_key_id"),
    "aws_secret_access_key": os.getenv("aws_secret_access_key"),
}

sys.path.insert(0, "/var/www/projects/silvaengine_auth")

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger()

from silvaengine_auth import Auth


class SilvaEngineAuthTest(unittest.TestCase):
    def setUp(self):
        self.auth = Auth(logger, **setting)
        logger.info("Initiate SilvaEngineAuthTest ...")

    def tearDown(self):
        logger.info("Destory SilvaEngineAuthTest ...")

    @unittest.skip("demonstrating skipping")
    def test_graphql_getpermissions(self):
        # query = """
        #     query($limit: Int!) {
        #         permissions(limit: $limit) {
        #             permissionId
        #             service
        #             action
        #             paths
        #             createdAt
        #             updatedAt
        #             updatedBy
        #             lastEvaluatedKey
        #         }
        #     }
        # """

        # variables = {"limit": 1}

        # query = """
        #     query($permissionId: String!) {
        #         permissions(permissionId: $permissionId) {
        #             permissionId
        #             service
        #             action
        #             paths
        #             createdAt
        #             updatedAt
        #             updatedBy
        #         }
        #     }
        # """

        # variables = {"permissionId": "666c6f90-a013-11eb-8016-0242ac120002"}

        query = """
            query($limit: Int!, $lastEvaluatedKey: String!) {
                permissions(limit: $limit, lastEvaluatedKey: $lastEvaluatedKey) {
                    permissionId
                    service
                    action
                    paths
                    createdAt
                    updatedAt
                    updatedBy
                    lastEvaluatedKey
                }
            }
        """

        variables = {
            "limit": 1,
            "lastEvaluatedKey": Utility.json_dumps(
                {
                    "service": {"S": "xyz"},
                    "permission_id": {"S": "666c6f90-a013-11eb-8016-0242ac120002"},
                }
            ),
        }

        payload = {"query": query, "variables": variables}

        response = self.auth.auth_graphql(**payload)
        logger.info(response)

    # @unittest.skip("demonstrating skipping")
    def test_graphql_getroles(self):
        # query = """
        #     query($limit: Int!) {
        #         roles(limit: $limit) {
        #             roleId
        #             name
        #             permissionIds
        #             userIds
        #             createdAt
        #             updatedAt
        #             updatedBy
        #         }
        #     }
        # """

        # variables = {"limit": 1}

        # query = """
        #     query($roleId: String!) {
        #         roles(roleId: $roleId) {
        #             roleId
        #             name
        #             permissionIds
        #             userIds
        #             createdAt
        #             updatedAt
        #             updatedBy
        #         }
        #     }
        # """

        # variables = {"roleId": "96f5172e-adde-11eb-8638-0242ac120002"}

        query = """
            query($limit: Int!, $lastEvaluatedKey: String!) {
                roles(limit: $limit, lastEvaluatedKey: $lastEvaluatedKey) {
                    roleId
                    name
                    permissionIds
                    userIds
                    createdAt
                    updatedAt
                    updatedBy
                }
            }
        """

        variables = {
            "limit": 1,
            "lastEvaluatedKey": Utility.json_dumps(
                {
                    "role_id": {"S": "96f5172e-adde-11eb-8638-0242ac120002"},
                }
            ),
        }

        payload = {"query": query, "variables": variables}

        response = self.auth.auth_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_graphql_insertupdatepermission(self):
        mutation = """
            mutation(
                    $permissionId: String!,
                    $service: String!,
                    $action: String!,
                    $paths: [String]!,
                    $updatedBy: String!
                ) {
                insertUpdatePermission(
                    permissionInput:{
                        permissionId: $permissionId,
                        service: $service,
                        action: $action,
                        paths: $paths,
                        updatedBy: $updatedBy
                    }
                ) {
                    permission{
                        permissionId
                        service
                        action
                        paths
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            "permissionId": "666c6f90-a013-11eb-8016-0242ac120002",
            "service": "xyz",
            "action": "read",
            "paths": ["abc", "edf"],
            "updatedBy": "99999",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.auth_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_graphql_insertupdaterole(self):
        mutation = """
            mutation(
                    $roleId: String!,
                    $name: String!,
                    $permissionIds: [String]!,
                    $userIds: [String]!,
                    $updatedBy: String!
                ) {
                insertUpdateRole(
                    roleInput:{
                        roleId: $roleId,
                        name: $name,
                        permissionIds: $permissionIds,
                        userIds: $userIds,
                        updatedBy: $updatedBy
                    }
                ) {
                    role{
                        roleId
                        name
                        permissionIds
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        # mutation = """
        #     mutation(
        #             $name: String!,
        #             $permissionIds: [String]!,
        #             $userIds: [String]!,
        #             $updatedBy: String!
        #         ) {
        #         insertUpdateRole(
        #             roleInput:{
        #                 name: $name,
        #                 permissionIds: $permissionIds,
        #                 userIds: $userIds,
        #                 updatedBy: $updatedBy
        #             }
        #         ) {
        #             role{
        #                 roleId
        #                 name
        #                 permissionIds
        #                 userIds
        #                 createdAt
        #                 updatedAt
        #                 updatedBy
        #             }
        #         }
        #     }
        # """

        variables = {
            "roleId": "96f5172e-adde-11eb-8638-0242ac120002",
            "name": "abx",
            "permissionIds": ["1234567890"],
            "userIds": ["abcxyz"],
            "updatedBy": "99999",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.auth_graphql(**payload)
        logger.info(response)


if __name__ == "__main__":
    unittest.main()
