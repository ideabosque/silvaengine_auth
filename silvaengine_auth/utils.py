import re

# Parse the graphql request's body to AST and extract fields from the AST
def extract_fields_from_ast(source, **kwargs):
    from graphql import parse
    from graphql.language.ast import SelectionSet

    def extract_by_recursion(selections, **kwargs):
        fs = []
        dpt = kwargs.get("deepth")

        if type(dpt) is not int or dpt < 1:
            dpt = None
        else:
            dpt -= 1

        for s in selections:
            if not (s.name.value in fs):
                fs.append(s.name.value.lower())

            if (
                (dpt is None or dpt > 0)
                and hasattr(s, "selection_set")
                and type(s.selection_set) is SelectionSet
                and type(s.selection_set.selections) is list
                and len(s.selection_set.selections) > 0
            ):
                return fs + extract_by_recursion(s.selection_set.selections, deepth=dpt)

        return fs

    result = dict()
    operation = kwargs.get("operation")
    deepth = kwargs.get("deepth")
    ast = parse(source)

    for od in ast.definitions:
        on = od.operation.lower()

        if operation and on != operation.lower():
            continue

        if on in result:
            result[on] += extract_by_recursion(
                od.selection_set.selections, deepth=deepth
            )
        else:
            result[on] = extract_by_recursion(
                od.selection_set.selections, deepth=deepth
            )

    for operation in result:
        result[operation] = list({}.fromkeys(result[operation]).keys())

    return result


class HttpVerb:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ALL = "*"


class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    restApiId = "<<restApiId>>"
    """ Replace the placeholder value with a default API Gateway API id to be used in the policy. 
    Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    region = "<<region>>"
    """ Replace the placeholder value with a default region to be used in the policy. 
    Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    stage = "<<stage>>"
    """ Replace the placeholder value with a default stage to be used in the policy. 
    Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError(
                "Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class"
            )
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError(
                "Invalid resource path: "
                + resource
                + ". Path should match "
                + self.pathRegex
            )

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = (
            "arn:aws:execute-api:"
            + self.region
            + ":"
            + self.awsAccountId
            + ":"
            + self.restApiId
            + "/"
            + self.stage
            + "/"
            + verb
            + "/"
            + resource
        )

        if effect.lower() == "allow":
            self.allowMethods.append(
                {"resourceArn": resourceArn, "conditions": conditions}
            )
        elif effect.lower() == "deny":
            self.denyMethods.append(
                {"resourceArn": resourceArn, "conditions": conditions}
            )

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            "Action": "execute-api:Invoke",
            "Effect": effect[:1].upper() + effect[1:].lower(),
            "Resource": [],
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod["conditions"] is None or len(curMethod["conditions"]) == 0:
                    statement["Resource"].append(curMethod["resourceArn"])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement["Resource"].append(curMethod["resourceArn"])
                    conditionalStatement["Condition"] = curMethod["conditions"]
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if (self.allowMethods is None or len(self.allowMethods) == 0) and (
            self.denyMethods is None or len(self.denyMethods) == 0
        ):
            raise NameError("No statements defined for the policy")

        policy = {
            "principalId": self.principalId,
            "policyDocument": {"Version": self.version, "Statement": []},
        }

        policy["policyDocument"]["Statement"].extend(
            self._getStatementForEffect("Allow", self.allowMethods)
        )
        policy["policyDocument"]["Statement"].extend(
            self._getStatementForEffect("Deny", self.denyMethods)
        )

        return policy


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
