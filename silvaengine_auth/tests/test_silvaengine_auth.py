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

        # variables = {"limit": 1}

        # query = """
        #     query getRoles(
        #             $limit: Int!
        #         ){
        #         roles(
        #             limit: $limit
        #         ){
        #             roleId
        #             name
        #             permissions{resourceId, permission}
        #             userIds
        #             createdAt
        #             updatedAt
        #             updatedBy
        #             lastEvaluatedKey
        #         }
        #     }
        # """

        # variables = {"resourceId": "666c6f90-a013-11eb-8016-0242ac120002"}

        query = """
            query getResources(
                    $limit: Int!,
                    $lastEvaluatedKey: String
                ){
                resources(
                    limit: $limit,
                    lastEvaluatedKey: $lastEvaluatedKey
                ){
                    resourceId
                    service
                    name
                    path
                    status
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
                    # "service": {"S": "xyz"},
                    "resource_id": {"S": "e0dff598-ae3d-11eb-94ae-0242ac120002"},
                }
            ),
        }

        payload = {"query": query, "variables": variables}
        response = self.auth.auth_graphql(**payload)
        logger.info(response)

    # @unittest.skip("demonstrating skipping")
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
        response = self.auth.auth_graphql(**payload)
        logger.info(response)

    # post / put / patch / delete <===> query / update / create / delete
    # put/patch === update
    # post == insert / create
    # delete == delete

    @unittest.skip("demonstrating skipping")
    def test_graphql_insertupdaterole(self):
        mutation = """
            mutation insertUpdateRole(
                    $roleId: String,
                    $name: String!,
                    $permissions: [PermissionInputType]!,
                    $userIds: [String]!,
                    $updatedBy: String!
                ) {
                insertUpdateRole(
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
                {"resourceId": "a81691d4-ae3a-11eb-8e18-0242ac120002", "permission": 15}
            ],
            "userIds": ["abc", "edf"],
            "updatedBy": "99999",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.auth_graphql(**payload)
        logger.info(response)


if __name__ == "__main__":
    unittest.main()
