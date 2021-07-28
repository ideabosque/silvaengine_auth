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
    "app_client_id": os.getenv("app_client_id"),
    "app_client_secret": os.getenv("app_client_secret"),
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

    @unittest.skip("demonstrating skipping")
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
                    $name: String!,
                    $permissions: [PermissionInputType]!,
                    $userIds: [String]!,
                    $updatedBy: String!
                    $isAdmin: Boolean!
                    $description: String!
                ) {
                createRole(
                    roleInput:{
                        name: $name,
                        permissions: $permissions,
                        userIds: $userIds,
                        updatedBy: $updatedBy
                        isAdmin: $isAdmin,
                        description: $description
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
                        isAdmin
                        description
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
            "description": "Manager",
            "isAdmin": True,
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

    # @unittest.skip("demonstrating skipping")
    def test_certificate(self):
        query = """
            query certificate(
                    $username: String!,
                    $password: String!
                ) {
                certificate(
                    username: $username,
                    password: $password
                ) {
                   idToken
                   refreshToken
                   permissions
                   context
                }
            }
        """

        variables = {
            "username": os.getenv("test_username"),
            "password": os.getenv("test_user_password"),
        }
        payload = {"query": query, "variables": variables}
        response = self.auth.login_graphql(**payload)
        print(response)
        print("##############")

    @unittest.skip("demonstrating skipping")
    def test_authorize(self):
        request = {
            "type": "REQUEST",
            "methodArn": "arn:aws:execute-api:us-west-2:305624596524:zi6fc6jh81/beta/POST/core/1/analytics_engine_graphql",
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/1/analytics_engine_graphql",
            "httpMethod": "ANY",
            "headers": {
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN",
                "Authorization": "eyJraWQiOiJPVzBkQXpiNlgwZ1FPNVNhamRycG1rWmFPNGJBR2hJRU9GaEJMRUZWTE9nPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwNzZkZTIyYS02ZWVkLTQ4MzYtYjRiYi1lYzA2ZjEyNzQzMTEiLCJhdWQiOiIxNTZvN3RvY243bTZhYTZhaDl0cGZmOWdscyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6Ijg0NTZmMDYzLWYzMDktNDRhMy05NTkwLTlkOWM1MDEyY2ZiMiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjI1MDUxMTYyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9lT3NFOE5ZbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYmFycnkueS5saXVAaG90bWFpbC5jb20iLCJleHAiOjE2MjUxMDg3NjIsImlhdCI6MTYyNTA1MTE2MiwiZW1haWwiOiJiYXJyeS55LmxpdUBob3RtYWlsLmNvbSJ9.YhL0ozDNazBI0cLRuvC77PSmsLgWfl9g55Rybu5NKLRU9GVWm8hcC9caCLYxa4xSIYv7XFBBMPb9IWwKr_gR9RBDwBDvJZk1TPpX12mi6hzm0BW8ClLPNqpWkIhOH_VrVVX7tYtk3SOQXa7vC6LiRC_M6dEOYLM_3kizrg-8Ilso9Bj5PbVh1U1OqWZ81rUTZNQ74_tlbGrOCChmG2_xJ-8syCsNFBU2BMU9uDW3NzpavCOKJgWF6D8UzgZNEvzEYij-qZswQ7ruh0sdxrZMxPbbWV_rLalZgB_lswyMlSXBx0sak7Nk314XNIoOxWJzgh8lsz-0gLYh_WqAyNk6ag",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "US",
                "Content-Length": "306",
                "content-type": "application/json",
                "Host": "zi6fc6jh81.execute-api.us-west-2.amazonaws.com",
                "origin": "electron://altair",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.7 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                "Via": "2.0 246b44c4747953e35657a81aebd7c7fb.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "ei6w42prkeVdB68nNQKY-Ij3pYavjcebDgrHoula3fdTkIH23T3Yng==",
                "X-Amzn-Trace-Id": "Root=1-60f78496-23771fd411e1c965332d8238",
                "x-api-key": "T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD",
                "X-Forwarded-For": "103.97.201.121, 130.176.93.71",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN"],
                "Authorization": [
                    "eyJraWQiOiJPVzBkQXpiNlgwZ1FPNVNhamRycG1rWmFPNGJBR2hJRU9GaEJMRUZWTE9nPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwNzZkZTIyYS02ZWVkLTQ4MzYtYjRiYi1lYzA2ZjEyNzQzMTEiLCJhdWQiOiIxNTZvN3RvY243bTZhYTZhaDl0cGZmOWdscyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6Ijg0NTZmMDYzLWYzMDktNDRhMy05NTkwLTlkOWM1MDEyY2ZiMiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjI1MDUxMTYyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9lT3NFOE5ZbGUiLCJjb2duaXRvOnVzZXJuYW1lIjoiYmFycnkueS5saXVAaG90bWFpbC5jb20iLCJleHAiOjE2MjUxMDg3NjIsImlhdCI6MTYyNTA1MTE2MiwiZW1haWwiOiJiYXJyeS55LmxpdUBob3RtYWlsLmNvbSJ9.YhL0ozDNazBI0cLRuvC77PSmsLgWfl9g55Rybu5NKLRU9GVWm8hcC9caCLYxa4xSIYv7XFBBMPb9IWwKr_gR9RBDwBDvJZk1TPpX12mi6hzm0BW8ClLPNqpWkIhOH_VrVVX7tYtk3SOQXa7vC6LiRC_M6dEOYLM_3kizrg-8Ilso9Bj5PbVh1U1OqWZ81rUTZNQ74_tlbGrOCChmG2_xJ-8syCsNFBU2BMU9uDW3NzpavCOKJgWF6D8UzgZNEvzEYij-qZswQ7ruh0sdxrZMxPbbWV_rLalZgB_lswyMlSXBx0sak7Nk314XNIoOxWJzgh8lsz-0gLYh_WqAyNk6ag"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["US"],
                "Content-Length": ["306"],
                "content-type": ["application/json"],
                "Host": ["zi6fc6jh81.execute-api.us-west-2.amazonaws.com"],
                "origin": ["electron://altair"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "User-Agent": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.7 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36"
                ],
                "Via": [
                    "2.0 246b44c4747953e35657a81aebd7c7fb.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "ei6w42prkeVdB68nNQKY-Ij3pYavjcebDgrHoula3fdTkIH23T3Yng=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-60f78496-23771fd411e1c965332d8238"],
                "x-api-key": ["T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD"],
                "X-Forwarded-For": ["103.97.201.121, 130.176.93.71"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": {},
            "multiValueQueryStringParameters": {},
            "pathParameters": {
                "area": "core",
                "proxy": "analytics_engine_graphql",
                "endpoint_id": "1",
            },
            "stageVariables": {},
            "requestContext": {
                "resourceId": "aljh9q",
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "CzGnnE87PHcF0uA=",
                "requestTime": "21/Jul/2021:02:21:10 +0000",
                "path": "/beta/core/1/analytics_engine_graphql",
                "accountId": "305624596524",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "zi6fc6jh81",
                "requestTimeEpoch": 1626834070911,
                "requestId": "1e957abf-6d2e-40a6-8cd0-fd66f37822b2",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "p3gex19qti",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.7 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "103.97.201.121",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "zi6fc6jh81.execute-api.us-west-2.amazonaws.com",
                "apiId": "zi6fc6jh81",
            },
        }

        response = self.auth.authorize(request, None)
        print("Response:", response)


if __name__ == "__main__":
    unittest.main()
