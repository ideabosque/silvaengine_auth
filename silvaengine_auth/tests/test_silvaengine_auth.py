#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"

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
    def test_graphql_get_resource_or_roles(self):
        # query = """
        #     query getResources(
        #             $limit: Int!
        #         ){
        #         resources(
        #             limit: $limit
        #         ){
        #             resourceId
        #             service
        #             name
        #             path
        #             status
        #             createdAt
        #             updatedAt
        #             updatedBy
        #             lastEvaluatedKey
        #         }
        #     }
        # # """

        variables = {"limit": 1}

        query = """
            query roles(
                    $limit: Int!
                    $lastEvaluatedKey: PageInputType
                ){
                roles(
                    limit: $limit
                    lastEvaluatedKey: $lastEvaluatedKey
                ){
                    items {
                        roleId
                        name
                        permissions{resourceId, permission}
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                    }
                    lastEvaluatedKey {
                        hashKey
                        rangeKey
                    }
                }
            }
        """

        # variables = {"resourceId": "666c6f90-a013-11eb-8016-0242ac120002"}

        # query = """
        #     query getResources(
        #             $limit: Int!,
        #             $lastEvaluatedKey: String
        #         ){
        #         resources(
        #             limit: $limit,
        #             lastEvaluatedKey: $lastEvaluatedKey
        #         ){
        #             resourceId
        #             service
        #             name
        #             path
        #             status
        #             createdAt
        #             updatedAt
        #             updatedBy
        #             lastEvaluatedKey
        #         }
        #     }
        # """

        # variables = {
        #     "limit": 1,
        #     "lastEvaluatedKey": Utility.json_dumps(
        #         {
        #             # "service": {"S": "xyz"},
        #             "resource_id": {"S": "e0dff598-ae3d-11eb-94ae-0242ac120002"},
        #         }
        #     ),
        # }

        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    # @unittest.skip("demonstrating skipping")
    def test_graphql_get_role(self):
        query = """
            query role(
                    $roleId: String
                ){
                role(
                    roleId: $roleId
                ){
                    roleId
                    name
                    permissions{resourceId, permission}
                    userIds
                    createdAt
                    updatedAt
                    updatedBy
                }
            }
        """
        variables = {"roleId": "11ef4284-da82-11eb-9e1a-0365a5eef1fa"}
        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_graphql_insertupdateresource(self):
        mutation = """
            mutation insertUpdateResource(
                    $resourceId: String!,
                    $service: String!,
                    $name: String!,
                    $path: String!,
                    $status: Int!,
                    $updatedBy: String!
                ) {
                insertUpdateResource(
                    resourceInput:{
                        resourceId: $resourceId,
                        service: $service,
                        name: $name,
                        path: $path,
                        status: $status,
                        updatedBy: $updatedBy
                    }
                ) {
                    resource{
                        resourceId
                        service
                        name
                        path
                        status
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            # "resourceId": "666c6f90-a013-11eb-8016-0242ac120002",
            "resourceId": "",
            "service": "abc",
            "name": "Product",
            "path": "/core/api/products",
            "status": 1,
            "updatedBy": "123",
        }

        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    # post / put / patch / delete <===> query / update / create / delete
    # put/patch === update
    # post == insert / create
    # delete == delete

    @unittest.skip("demonstrating skipping")
    def test_create_role(self):
        mutation = """
            mutation createRole(
                    $roleId: String,
                    $name: String!,
                    $permissions: [PermissionInputType]!,
                    $userIds: [String]!,
                    $updatedBy: String!
                ) {
                createRole(
                    roleInput:{
                        roleId: $roleId,
                        name: $name,
                        permissions: $permissions,
                        userIds: $userIds,
                        updatedBy: $updatedBy
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions{resourceId, permission}
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            # "roleId": "666c6f90-a013-11eb-8016-0242ac120002",
            "name": "Manager",
            "permissions": [{"resourceId": "Just for test", "permission": 15}],
            "userIds": ["39f3cc57-e5b3-422e-a140-6c316d308b2b"],
            "updatedBy": "23456",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_update_role(self):
        mutation = """
            mutation updateRole(
                    $roleId: String,
                    $name: String!,
                    $permissions: [PermissionInputType]!,
                    $userIds: [String]!,
                    $updatedBy: String!
                ) {
                updateRole(
                    roleInput:{
                        roleId: $roleId,
                        name: $name,
                        permissions: $permissions,
                        userIds: $userIds,
                        updatedBy: $updatedBy
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions{resourceId, permission}
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            # "roleId": "666c6f90-a013-11eb-8016-0242ac120002",
            "name": "test",
            "permissions": [
                {"resourceId": "7f359f30-af16-11eb-8bb3-0242ac180002", "permission": 1}
            ],
            "userIds": ["39f3cc57-e5b3-422e-a140-6c316d308b2b"],
            "updatedBy": "99999",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_delete_role(self):
        mutation = """
            mutation deleteRole(
                    $roleId: String,
                ) {
                deleteRole(
                    roleInput:{
                        roleId: $roleId,
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions{resourceId, permission}
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            "roleId": "0c6547b8-b1a4-11eb-b267-0242ac180002",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)


if __name__ == "__main__":
    unittest.main()
