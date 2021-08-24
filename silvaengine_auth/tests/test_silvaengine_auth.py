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

    # post / put / patch / delete <===> query / update / create / delete
    # put/patch === update
    # post == insert / create
    # delete == delete

    @unittest.skip("demonstrating skipping")
    def test_create_role(self):
        mutation = """
            mutation createRole(
                    $name: String!,
                    $permissions: [PermissionInputType]!
                    $updatedBy: String!
                    $description: String!
                    $status: Boolean
                ) {
                createRole(
                    roleInput:{
                        name: $name,
                        permissions: $permissions
                        updatedBy: $updatedBy
                        description: $description
                        status: $status
                    }
                ) {
                    role{
                        roleId
                        name
                        permissions {
                            resourceId
                            permissions {
                                operationName
                                exclude
                            }
                        }
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
                {
                    "resourceId": "053429072013b1fc6eeac9555cd4618b",
                    "permissions": [
                        {
                            "operationName": "paginateProducts",
                            "operation": "query",
                            "exclude": [],
                        },
                        {
                            "operationName": "showProduct",
                            "exclude": [],
                            "operation": "query",
                        },
                    ],
                },
            ],
            "updatedBy": "setup",
            "description": "Product engines",
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
            "roleId": "56ff4230-03dc-11ec-8258-0242ac120002",
            "permissions": [
                {
                    "resourceId": "053429072013b1fc6eeac9555cd4618b",
                    "permissions": [
                        {
                            "operationName": "paginateProducts",
                            "exclude": [],
                        },
                        {
                            "operationName": "showProduct",
                            "exclude": ["companyCode"],
                        },
                    ],
                },
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
                ){

                }
            }
        """

        variables = {
            "roleId": "56ff4230-03dc-11ec-8258-0242ac120002",
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

    # @unittest.skip("demonstrating skipping")
    def test_verify_permissions(self):
        request = {
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/1/product_engine_graphql",
            "httpMethod": "POST",
            "headers": {
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN",
                "Authorization": "eyJraWQiOiJPVzBkQXpiNlgwZ1FPNVNhamRycG1rWmFPNGJBR2hJRU9GaEJMRUZWTE9nPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwNzZkZTIyYS02ZWVkLTQ4MzYtYjRiYi1lYzA2ZjEyNzQzMTEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJ0ZWFtcyI6IntcIjM1N1wiOiB7XCJ0ZWFtX2lkXCI6IDM1NywgXCJ2ZW5kb3JfaWRcIjogMTA3MzMsIFwiZXJwX3ZlbmRvcl9yZWZcIjogNDEyOTJ9LCBcIjQ1MFwiOiB7XCJ0ZWFtX2lkXCI6IDQ1MCwgXCJ2ZW5kb3JfaWRcIjogODg4OH0sIFwiNDcwXCI6IHtcInRlYW1faWRcIjogNDcwLCBcInZlbmRvcl9pZFwiOiAxMjN9LCBcIjQ3OVwiOiB7XCJ0ZWFtX2lkXCI6IDQ3OSwgXCJ2ZW5kb3JfaWRcIjogMTA3NjMsIFwiZXJwX3ZlbmRvcl9yZWZcIjogNDEyOTJ9LCBcIjUwNFwiOiB7XCJ0ZWFtX2lkXCI6IDUwNH0sIFwiNTEyXCI6IHtcInRlYW1faWRcIjogNTEyfSwgXCI1MTRcIjoge1widGVhbV9pZFwiOiA1MTQsIFwidmVuZG9yX2lkXCI6IDF9LCBcIjUxNVwiOiB7XCJ0ZWFtX2lkXCI6IDUxNSwgXCJ2ZW5kb3JfaWRcIjogMX0sIFwiNTE2XCI6IHtcInRlYW1faWRcIjogNTE2LCBcInZlbmRvcl9pZFwiOiAxfSwgXCI1MTdcIjoge1widGVhbV9pZFwiOiA1MTcsIFwidmVuZG9yX2lkXCI6IDF9fSIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbVwvdXMtd2VzdC0yX2VPc0U4TllsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJiYXJyeS55LmxpdUBob3RtYWlsLmNvbSIsImlzX2FkbWluIjoiMCIsImF1ZCI6IjE1Nm83dG9jbjdtNmFhNmFoOXRwZmY5Z2xzIiwiZXZlbnRfaWQiOiJiMGQ3Y2U3Ny1iOTI1LTQyZTktYTJmMy0xOTRlOWIzMjhjYzQiLCJ1c2VyX2lkIjoiMTkwOCIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjI5Nzg3OTc5LCJleHAiOjE2Mjk4NDU1NzksImlhdCI6MTYyOTc4Nzk3OSwic2VsbGVyX2lkIjoiMjAxOCIsImVtYWlsIjoiYmFycnkueS5saXVAaG90bWFpbC5jb20ifQ.aFExc_xBVQT0Zv7ba6ePMzfDxwhheegrr1f2tZPrjx4ZyNfw89zh3F19V_FWCAYankvFoRaw5G-kDrjgstPxPTPFSs0MoDrLN3tiRP58Rv6iLeRCKywjSB258TNmzSzxjB-Q6_p2caYo39mCXECxq0RIKDFDu90WtaIVZKAzzqg9M7eE-ZBbgnOPmVEIpbyV2hvaGPHT-_GXFbP5rL3ErgPIuA-KnA05hM0L6z9e3L1RmEDyNx7gdrlHtaj4ip6pSUawwFivVJPf7yvxv6B8wWsDPDHdHifVFZwAh-TRjxv6tWK9FLtpH12Jb9JxoT9Qw4hXgIUJoZvioiV_RqOndg",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "HK",
                "content-type": "application/json",
                "Host": "zi6fc6jh81.execute-api.us-west-2.amazonaws.com",
                "origin": "electron://altair",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "seller_id": "2018",
                "team_id": "357",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                "Via": "2.0 08c8928e40ae368a9e7c75aead506958.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "nBPNsDko8ntApSvAm_xqsqN_WyLKpWfUbHk525zevEytzxY0KEP1bA==",
                "X-Amzn-Trace-Id": "Root=1-6124c02d-2dc19f0124ef23941942ca10",
                "x-api-key": "T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD",
                "X-Forwarded-For": "103.97.201.121, 130.176.25.145",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN"],
                "Authorization": [
                    "eyJraWQiOiJPVzBkQXpiNlgwZ1FPNVNhamRycG1rWmFPNGJBR2hJRU9GaEJMRUZWTE9nPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwNzZkZTIyYS02ZWVkLTQ4MzYtYjRiYi1lYzA2ZjEyNzQzMTEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJ0ZWFtcyI6IntcIjM1N1wiOiB7XCJ0ZWFtX2lkXCI6IDM1NywgXCJ2ZW5kb3JfaWRcIjogMTA3MzMsIFwiZXJwX3ZlbmRvcl9yZWZcIjogNDEyOTJ9LCBcIjQ1MFwiOiB7XCJ0ZWFtX2lkXCI6IDQ1MCwgXCJ2ZW5kb3JfaWRcIjogODg4OH0sIFwiNDcwXCI6IHtcInRlYW1faWRcIjogNDcwLCBcInZlbmRvcl9pZFwiOiAxMjN9LCBcIjQ3OVwiOiB7XCJ0ZWFtX2lkXCI6IDQ3OSwgXCJ2ZW5kb3JfaWRcIjogMTA3NjMsIFwiZXJwX3ZlbmRvcl9yZWZcIjogNDEyOTJ9LCBcIjUwNFwiOiB7XCJ0ZWFtX2lkXCI6IDUwNH0sIFwiNTEyXCI6IHtcInRlYW1faWRcIjogNTEyfSwgXCI1MTRcIjoge1widGVhbV9pZFwiOiA1MTQsIFwidmVuZG9yX2lkXCI6IDF9LCBcIjUxNVwiOiB7XCJ0ZWFtX2lkXCI6IDUxNSwgXCJ2ZW5kb3JfaWRcIjogMX0sIFwiNTE2XCI6IHtcInRlYW1faWRcIjogNTE2LCBcInZlbmRvcl9pZFwiOiAxfSwgXCI1MTdcIjoge1widGVhbV9pZFwiOiA1MTcsIFwidmVuZG9yX2lkXCI6IDF9fSIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbVwvdXMtd2VzdC0yX2VPc0U4TllsZSIsImNvZ25pdG86dXNlcm5hbWUiOiJiYXJyeS55LmxpdUBob3RtYWlsLmNvbSIsImlzX2FkbWluIjoiMCIsImF1ZCI6IjE1Nm83dG9jbjdtNmFhNmFoOXRwZmY5Z2xzIiwiZXZlbnRfaWQiOiJiMGQ3Y2U3Ny1iOTI1LTQyZTktYTJmMy0xOTRlOWIzMjhjYzQiLCJ1c2VyX2lkIjoiMTkwOCIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjI5Nzg3OTc5LCJleHAiOjE2Mjk4NDU1NzksImlhdCI6MTYyOTc4Nzk3OSwic2VsbGVyX2lkIjoiMjAxOCIsImVtYWlsIjoiYmFycnkueS5saXVAaG90bWFpbC5jb20ifQ.aFExc_xBVQT0Zv7ba6ePMzfDxwhheegrr1f2tZPrjx4ZyNfw89zh3F19V_FWCAYankvFoRaw5G-kDrjgstPxPTPFSs0MoDrLN3tiRP58Rv6iLeRCKywjSB258TNmzSzxjB-Q6_p2caYo39mCXECxq0RIKDFDu90WtaIVZKAzzqg9M7eE-ZBbgnOPmVEIpbyV2hvaGPHT-_GXFbP5rL3ErgPIuA-KnA05hM0L6z9e3L1RmEDyNx7gdrlHtaj4ip6pSUawwFivVJPf7yvxv6B8wWsDPDHdHifVFZwAh-TRjxv6tWK9FLtpH12Jb9JxoT9Qw4hXgIUJoZvioiV_RqOndg"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["HK"],
                "content-type": ["application/json"],
                "Host": ["zi6fc6jh81.execute-api.us-west-2.amazonaws.com"],
                "origin": ["electron://altair"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "seller_id": ["2018"],
                "team_id": ["357"],
                "User-Agent": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36"
                ],
                "Via": [
                    "2.0 08c8928e40ae368a9e7c75aead506958.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "nBPNsDko8ntApSvAm_xqsqN_WyLKpWfUbHk525zevEytzxY0KEP1bA=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6124c02d-2dc19f0124ef23941942ca10"],
                "x-api-key": ["T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD"],
                "X-Forwarded-For": ["103.97.201.121, 130.176.25.145"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": {
                "area": "core",
                "proxy": "product_engine_graphql",
                "endpoint_id": "1",
            },
            "stageVariables": None,
            "requestContext": {
                "resourceId": "aljh9q",
                "authorizer": {
                    "sub": "076de22a-6eed-4836-b4bb-ec06f1274311",
                    "email_verified": "true",
                    "s_vendor_id": "S10763",
                    "custom_context_hooks": "relation_engine:RelationEngine:get_seller_role_relation",
                    "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_eOsE8NYle",
                    "principalId": "/core/1/product_engine_graphql",
                    "cognito:username": "barry.y.liu@hotmail.com",
                    "integrationLatency": 7415,
                    "team_id": "357",
                    "erp_vendor_ref": "41292",
                    "is_admin": "0",
                    "aud": "156o7tocn7m6aa6ah9tpff9gls",
                    "event_id": "b0d7ce77-b925-42e9-a2f3-194e9b328cc4",
                    "user_id": "1908",
                    "token_use": "id",
                    "auth_time": "1629787979",
                    "vendor_id": "10733",
                    "exp": "1629845579",
                    "iat": "1629787979",
                    "seller_id": "2018",
                    "email": "barry.y.liu@hotmail.com",
                },
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "EkL3EGo5PHcFaaw=",
                "requestTime": "24/Aug/2021:09:47:25 +0000",
                "path": "/beta/core/1/product_engine_graphql",
                "accountId": "305624596524",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "zi6fc6jh81",
                "requestTimeEpoch": 1629798445088,
                "requestId": "25e841c6-3aff-4cdc-b6df-bd7c68878f90",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "T5u3V0P1iv3rF44rRDEbb8M4Mo3g974n408C7MUD",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "p3gex19qti",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
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
            "body": '{"query":"query showProduct($productIdentifier: String!) {\\n  showProduct(productIdentifier: $productIdentifier) {\\n    product {\\n      identifier\\n      enabled\\n      createdAt\\n      updatedAt\\n      productDocuments {\\n        id\\n        productIdentifier\\n        documentId\\n        approvalCode\\n        approvedBy\\n        approvedDate\\n        approvalNotes\\n        publishedFlag\\n        publishedBy\\n        publishedDate\\n        document {\\n          documentId\\n          docTypeId\\n          sellerId\\n          fileNameOrig\\n          filePathS3\\n          expireDate\\n          customTag\\n          docType {\\n            docTypeId\\n            typeName\\n            requiredFlag\\n            sortOrder\\n            forQc\\n            forProduct\\n            forFactory\\n            forShipment\\n            uploadOnlyFlag\\n            expireFlag\\n            docPrefix\\n            docTypeGroupId\\n          }\\n        }\\n      }\\n      status\\n      shelfLifeUom\\n      shelfLife\\n      url\\n      erpItemId\\n      magentoSku\\n      sellerCode\\n      companyCode\\n      factoryCode\\n      productName\\n      countryOfOrigin\\n      usage\\n      highlights\\n      description\\n      storageCondition\\n      magentoCategories\\n      magentoApplications\\n      packagingSize\\n      maxPrice {\\n        amount\\n        currency\\n      }\\n      minPrice {\\n        amount\\n        currency\\n      }\\n      sellerSku\\n      innerPackaging\\n      desiccant\\n      netWeight\\n      grossWeight\\n      minOrderQty\\n      pkgPerPallet\\n      containerWidth\\n      containerHeight\\n      containerLength\\n      docReady\\n      docZipReady\\n    }\\n  }\\n}","variables":{"productIdentifier":"uuid-test-io-product-213123"},"operationName":"showProduct"}',
            "isBase64Encoded": False,
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-west-2:305624596524:function:silvaengine_microcore",
                "config": {
                    "auth_required": True,
                    "class_name": "ProductEngine",
                    "funct_type": "RequestResponse",
                    "graphql": True,
                    "methods": ["POST"],
                    "module_name": "product_engine",
                    "operations": {
                        "mutation": [
                            "updateProductModel",
                            "deleteProductModel",
                            "createPromotionPrice",
                            "createIoProductTerm",
                            "createProduct",
                            "updateProduct",
                            "createProductModel",
                            "setMultipleProduct",
                            "deleteProduct",
                            "createProductTerm",
                            "setProductWarehouses",
                            "deleteProductTerm",
                            "setMultipleProductModel",
                            "deletePromotionPrice",
                            "deleteIoProductTerm",
                            "setProductPrice",
                        ],
                        "query": [
                            "paginateProducts",
                            "showProduct",
                            "paginateProductPackages",
                            "paginateProductModels",
                            "showProductModel",
                            "productOverView",
                            "productPriceList",
                            "productPromotions",
                            "paginateIoProductTerms",
                            "paginateProductTerms",
                            "paginateProductWarehouse",
                        ],
                    },
                    "setting": "product_engine",
                },
                "function": "product_engine_graphql",
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
            "userId": "076de22a-6eed-4836-b4bb-ec06f1274311",
            "roleId": "76633ace-03e0-11ec-8d77-0242ac120002",
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
