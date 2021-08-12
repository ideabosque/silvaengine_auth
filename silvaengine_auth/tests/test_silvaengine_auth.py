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
        variables = {"roleId": "27fae565-efaf-11eb-a5cd-d79a21e9d8bf"}
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
            "name": "Test",
            "permissions": [
                {"resourceId": "053429072013b1fc6eeac9555cd4618b", "permission": 15}
            ],
            "userIds": [],
            "updatedBy": "setup",
            "description": "",
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

    @unittest.skip("demonstrating skipping")
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

    # @unittest.skip("demonstrating skipping")
    def test_authorize(self):
        request = {
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/subscription_management_graphql",
            "httpMethod": "POST",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9,cy;q=0.8,en;q=0.7,zh-TW;q=0.6",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJjZGM5YWU4MC1lNmMxLTQyOGMtYmQ2MC1mNzM3YTY4ODMzZDciLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODU4NDk5NCwiZXhwIjoxNjI4NjU2OTk0LCJpYXQiOjE2Mjg1ODQ5OTQsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.SVn6Uw4HMrfOgsySaA8uYaLY4bl0cDbDsuEmxCZyn28lca3ATr3Bexkk0YHXLlqQv215rZuTILxNk0Rg_5Z27ZxbpfBTOQBHgioV2vNtvgEbwF74cfHfPl0SDG58-CE6N2M4P1XUk3d8Gl2pBAMNGRATlF_cHdIbYZzCUo8somFd9hWXCw2lrS5Og7KvAOiWguqjU-BRMXgsqSx0a6InCOnrhex5W3kecPeFsfDEtKeTxoCPx0K_5DuTV7SmleMrgOMhC6o-rWM3xveS0szMLOLFNlGaE94lThxzzZat9ZeTxBzprynl4eylhrWmw7Hv54BgCY9bJfMsGlZUptahpQ",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "TW",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Via": "2.0 23bee510a951c47c4c1082b3e720b091.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "UQvnpcs8yo4CP__tSBG3-CGuG___WWCt49xuQ_QC9QBh91odXC9Hlw==",
                "X-Amzn-Trace-Id": "Root=1-6114d543-61ca25da51153e4326ceea3b",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "61.221.4.123, 52.46.62.100",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json, text/plain, */*"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN,zh;q=0.9,cy;q=0.8,en;q=0.7,zh-TW;q=0.6"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJjZGM5YWU4MC1lNmMxLTQyOGMtYmQ2MC1mNzM3YTY4ODMzZDciLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODU4NDk5NCwiZXhwIjoxNjI4NjU2OTk0LCJpYXQiOjE2Mjg1ODQ5OTQsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.SVn6Uw4HMrfOgsySaA8uYaLY4bl0cDbDsuEmxCZyn28lca3ATr3Bexkk0YHXLlqQv215rZuTILxNk0Rg_5Z27ZxbpfBTOQBHgioV2vNtvgEbwF74cfHfPl0SDG58-CE6N2M4P1XUk3d8Gl2pBAMNGRATlF_cHdIbYZzCUo8somFd9hWXCw2lrS5Og7KvAOiWguqjU-BRMXgsqSx0a6InCOnrhex5W3kecPeFsfDEtKeTxoCPx0K_5DuTV7SmleMrgOMhC6o-rWM3xveS0szMLOLFNlGaE94lThxzzZat9ZeTxBzprynl4eylhrWmw7Hv54BgCY9bJfMsGlZUptahpQ"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["TW"],
                "content-type": ["application/json"],
                "Host": ["3fizlvttp4.execute-api.us-east-1.amazonaws.com"],
                "origin": ["http://localhost:3000"],
                "Referer": ["http://localhost:3000/"],
                "sec-ch-ua": [
                    '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"'
                ],
                "sec-ch-ua-mobile": ["?0"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "User-Agent": [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
                ],
                "Via": [
                    "2.0 23bee510a951c47c4c1082b3e720b091.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "UQvnpcs8yo4CP__tSBG3-CGuG___WWCt49xuQ_QC9QBh91odXC9Hlw=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6114d543-61ca25da51153e4326ceea3b"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["61.221.4.123, 52.46.62.100"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": {
                "area": "core",
                "proxy": "subscription_management_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": None,
            "requestContext": {
                "resourceId": "d5y1px",
                "authorizer": {
                    "principalId": "/core/api/subscription_management_graphql",
                    "integrationLatency": 6983,
                },
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "D8ZCkFMBIAMFwRA=",
                "requestTime": "12/Aug/2021:08:01:07 +0000",
                "path": "/beta/core/api/subscription_management_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1628755267489,
                "requestId": "3d5bcb92-d05c-4cff-ac41-4f17e55848dd",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "61.221.4.123",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "body": '{"query":"query($email: String!) {\\n                    mage2Token(email: $email) {\\n                        token\\n                    }\\n                }","variables":{"email":"edward@maginx.com"}}',
            "isBase64Encoded": False,
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": False,
                    "class_name": "SubscriptionManagementEngine",
                    "funct_type": "RequestResponse",
                    "graphql": True,
                    "methods": ["POST"],
                    "module_name": "subscription_management_engine",
                    "operations": {
                        "create": ["insertServiceSubscription"],
                        "delete": ["deleteServiceSubscription"],
                        "query": ["serviceSubscriptions", "mage2Token"],
                        "update": ["updateServiceSubscription"],
                    },
                    "setting": "subscription_management_engine",
                },
                "function": "subscription_management_graphql",
            },
        }

        response = self.auth.authorize(request, None)
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_create_relationship(self):
        mutation = """
            mutation createRelationship(
                    $groupId: String!,
                    $userId: String!,
                    $roleId: String!,
                    $updatedBy: String!
                    $status: Boolean
                ) {
                createRelationship(
                    input:{
                        groupId: $groupId,
                        userId: $userId,
                        roleId: $roleId,
                        updatedBy: $updatedBy
                        status: $status
                    }
                ) {
                    relationship{
                        groupId
                        userId
                        roleId
                        updatedBy
                        status
                    }
                }
            }
        """

        variables = {
            # "roleId": "666c6f90-a013-11eb-8016-0242ac120002",
            "groupId": "357",
            "userId": "49780567-2208-4922-8c12-b283e69543c6",
            "roleId": "b22aefa3-f365-11eb-b465-ef992f87a3fa",
            "updatedBy": "setup",
            "status": True,
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)


if __name__ == "__main__":
    unittest.main()
