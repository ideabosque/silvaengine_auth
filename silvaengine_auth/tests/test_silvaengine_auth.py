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

    # @unittest.skip("demonstrating skipping")
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

        variables = {"limit": 10, "ownerId": "2018"}

        query = """
            query roles(
                    $limit: Int!
                    $lastEvaluatedKey: PageInputType
                    $ownerId: String
                ){
                roles(
                    limit: $limit
                    lastEvaluatedKey: $lastEvaluatedKey
                    ownerId: $ownerId
                ){
                    items {
                        roleId
                        name
                        permissions{resourceId, permission}
                        userIds
                        createdAt
                        updatedAt
                        updatedBy
                        ownerId
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
                    $updatedBy: String!
                    $isAdmin: Boolean!
                    $description: String!
                    $ownerId: String
                    $status: Boolean
                ) {
                createRole(
                    roleInput:{
                        name: $name,
                        permissions: $permissions,
                        updatedBy: $updatedBy
                        isAdmin: $isAdmin,
                        description: $description
                        ownerId: $ownerId
                        status: $status
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions{resourceId, permission}
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
            "name": "Administrator",
            "permissions": [
                {"resourceId": "053429072013b1fc6eeac9555cd4618b", "permission": 15},
                {"resourceId": "16477cc4459ef3fda28ae622e993782f", "permission": 15},
                {"resourceId": "30162dce4320708c97af61906551c157", "permission": 15},
                {"resourceId": "3d3f12d147fb9252f2cc296def8210c0", "permission": 15},
                {"resourceId": "50edc9c01a6a79f496b95b36e3f460be", "permission": 15},
                {"resourceId": "530e5b45de1ea4a8cd32e74c115a7014", "permission": 15},
                {"resourceId": "5466e004123f67a995931490509e54a0", "permission": 15},
                {"resourceId": "832be4700056ff454e4129f954c8c1f7", "permission": 15},
                {"resourceId": "962dfa1df6b4fd684503ecce6320f6ba", "permission": 15},
                {"resourceId": "cbb25a1d81164e7d22703a90f4dd4523", "permission": 15},
                {"resourceId": "db1d5fcb2d0b692f2a423e2f2ae23247", "permission": 15},
                {"resourceId": "fa6ac17f060bf019b5e25b43157102fe", "permission": 15},
                {"resourceId": "fc4ec1d9a95d73ff981e8f95a3e3a3b1", "permission": 15},
            ],
            "updatedBy": "setup",
            "description": "",
            "isAdmin": True,
            "ownerId": 2019,
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_update_role(self):
        mutation = """
            mutation updateRole(
                    $roleId: String!,
                    $permissions: [PermissionInputType]
                ) {
                updateRole(
                    roleInput:{
                        roleId: $roleId,
                        permissions: $permissions
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions{resourceId, permission}
                        createdAt
                        updatedAt
                        updatedBy
                        isAdmin
                        description
                        status
                        ownerId
                    }
                }
            }
        """

        variables = {
            "roleId": "0f9cc991-fb57-11eb-805c-fba8500c5957",
            "permissions": [
                {"resourceId": "053429072013b1fc6eeac9555cd4618b", "permission": 15},
            ],
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

    @unittest.skip("demonstrating skipping")
    def test_authorize(self):
        request = {
            "type": "REQUEST",
            "methodArn": "arn:aws:execute-api:us-east-1:785238679596:3fizlvttp4/beta/POST/core/api/company_engine_graphql",
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/company_engine_graphql",
            "httpMethod": "ANY",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "CN",
                "Content-Length": "2944",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "seller_id": "2018",
                "team_id": "357",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                "Via": "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA==",
                "X-Amzn-Trace-Id": "Root=1-6114dc3f-19c01adf1f4423e86881251a",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "220.191.46.189, 130.176.132.189",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json, text/plain, */*"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN,zh;q=0.9"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["CN"],
                "Content-Length": ["2944"],
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
                "seller_id": ["2018"],
                "team_id": ["357"],
                "User-Agent": [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
                ],
                "Via": [
                    "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6114dc3f-19c01adf1f4423e86881251a"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["220.191.46.189, 130.176.132.189"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": {},
            "multiValueQueryStringParameters": {},
            "pathParameters": {
                "area": "core",
                "proxy": "company_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": {},
            "requestContext": {
                "resourceId": "d5y1px",
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "D8daBGpQoAMFwXg=",
                "requestTime": "12/Aug/2021:08:30:55 +0000",
                "path": "/beta/core/api/company_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1628757055955,
                "requestId": "d925a6f0-e7d9-414f-acbe-31f4c379bd07",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "220.191.46.189",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": False,
                    "class_name": "CompanyEngine",
                    "funct_type": "RequestResponse",
                    "graphql": False,
                    "methods": ["GET", "POST"],
                    "module_name": "company_engine",
                    "setting": "seller_engine_graphql",
                },
                "function": "company_engine_graphql",
            },
        }

        response = self.auth.authorize(request, None)
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_verify_permissions(self):
        request = {
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/seller_engine_graphql",
            "httpMethod": "POST",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "CN",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "seller_id": "2018",
                "team_id": "357",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                "Via": "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "9C9P6OlEQ2cAcpeSOJL8vRTaMTgSBPcGyByodP9at2DVB4LBQZTMBQ==",
                "X-Amzn-Trace-Id": "Root=1-6114ddae-5107129900a9f0de7519beac",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "220.191.46.189, 130.176.132.173",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json, text/plain, */*"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN,zh;q=0.9"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["CN"],
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
                "seller_id": ["2018"],
                "team_id": ["357"],
                "User-Agent": [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
                ],
                "Via": [
                    "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "9C9P6OlEQ2cAcpeSOJL8vRTaMTgSBPcGyByodP9at2DVB4LBQZTMBQ=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6114ddae-5107129900a9f0de7519beac"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["220.191.46.189, 130.176.132.173"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": {
                "area": "core",
                "proxy": "seller_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": None,
            "requestContext": {
                "resourceId": "d5y1px",
                "authorizer": {
                    "sub": "49780567-2208-4922-8c12-b283e69543c6",
                    "email_verified": "true",
                    "s_vendor_id": "S10763",
                    "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_GMvUhaxRs",
                    "principalId": "/core/api/seller_engine_graphql",
                    "cognito:username": "edward@maginx.com",
                    "integrationLatency": 270,
                    "is_admin": "0",
                    "aud": "et3i1tpbbmb41eogrdlp5qcsj",
                    "event_id": "0ea41081-a43b-425e-b938-645be70c9840",
                    "token_use": "id",
                    "auth_time": "1628729691",
                    "exp": "1628801691",
                    "iat": "1628729691",
                    "seller_id": "2018",
                    "email": "edward@maginx.com",
                },
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "D8eTXGEmIAMFe3g=",
                "requestTime": "12/Aug/2021:08:37:02 +0000",
                "path": "/beta/core/api/seller_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1628757422906,
                "requestId": "68453c99-2751-48aa-bbdf-105b3a43ac36",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "220.191.46.189",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "body": '{"query":"query Sellers(\\n\\t$first: Int,\\n\\t$sort: [SellerSortEnum]\\n) {\\n\\tsellers (\\n\\t\\tfirst: $first,\\n\\t\\tsort: $sort\\n\\t) {\\n\\t\\tedges {\\n\\t\\t\\tnode {\\n\\t\\t\\t\\tkey:sellerId\\n\\t\\t\\t\\tsellerId\\n\\t\\t\\t\\tsellerName\\n\\t\\t\\t}\\n\\t\\t}\\n\\t\\tsellerTotalCount\\n\\t}\\n}","variables":{"first":1000,"sort":["SELLER_NAME_DESC"]}}',
            "isBase64Encoded": False,
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": True,
                    "class_name": "SellerEngine",
                    "funct_type": "RequestResponse",
                    "graphql": True,
                    "methods": ["POST"],
                    "module_name": "seller_engine",
                    "operations": {
                        "create": ["insertSeller"],
                        "delete": ["deleteSeller"],
                        "query": ["sellers"],
                        "update": ["updateSeller"],
                    },
                    "setting": "seller_engine",
                },
                "function": "seller_engine_graphql",
            },
        }
        response = self.auth.verify_permission(request, None)
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

    @unittest.skip("demonstrating skipping")
    def test_update_relationship(self):
        mutation = """
            mutation updateRelationship(
                    $relationshipId: String!,
                    $groupId: String
                ) {
                updateRelationship(
                    input:{
                        groupId: $groupId,
                        relationshipId: $relationshipId
                    }
                ) {
                    relationship{
                        groupId
                        userId
                        roleId
                        updatedBy
                        status
                        updatedAt
                    }
                }
            }
        """

        variables = {
            "relationshipId": "0b4cf942-fb84-11eb-a0f7-6df87694cc69",
            "groupId": "357",
        }

        payload = {"mutation": mutation, "variables": variables}

        response = self.auth.role_graphql(**payload)
        logger.info(response)


if __name__ == "__main__":
    unittest.main()
