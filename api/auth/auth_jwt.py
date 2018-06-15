"""
auth_jwt.py: encapsulates all lambda functions related to JWT authentication
"""
__author__ = "Rafael Pelegrini Domingues"
__copyright__ = "Copyright 2018, Bain & Co"

#base imports
import os
import re
import time
import logging
import hashlib
import binascii
import json
import traceback
from base64 import b64decode

#utilities imports
import boto3
from botocore.exceptions import ClientError
import jose
import requests

# local imports

#get running environment
ENVIRONMENT = os.environ['ENV']

#common resources for multiple lambda requests
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
LAMBDA_CLIENT = boto3.client('lambda')
KMS_CLIENT = boto3.client('kms')

#configure access to lambda configurations
DYNAMO_DB = boto3.resource('dynamodb', region_name='us-west-2')
CONFIGURATION_TABLE = DYNAMO_DB.Table('lambda-config')
USER_TABLE = DYNAMO_DB.Table('user_' + ENVIRONMENT)
REPORT_TABLE = DYNAMO_DB.Table('health_report_' + ENVIRONMENT)

try:
    DYN_CONF = CONFIGURATION_TABLE.get_item(Key={'stage':ENVIRONMENT})['Item']
    PUBLIC_KEY = KMS_CLIENT.decrypt(CiphertextBlob=b64decode(DYN_CONF['AUTH_PUBLIC_KEY']))['Plaintext']
    PRIVATE_KEY = KMS_CLIENT.decrypt(CiphertextBlob=b64decode(DYN_CONF['AUTH_PRIVATE_KEY']))['Plaintext']
except ClientError as e:
    LOGGER.error(e.response['Error']['Message'])
except Exception:
    LOGGER.error(traceback.print_exc())

def auth_master_login_jwt(event, context):
    """AWS_LAMBDA:auth_master_login_jwt
    Authenticate a valid code/password combination.

    :param code: User identification code.
    :type code: str.
    :param password: User password.
    :type password: str.
    :returns: str -- Authentication token used for API calls.

    """
    try:
        #generate password hash for comparison, a slow hash with multiple iterations is used to difficult attacks
        binary_hash = hashlib.pbkdf2_hmac(
            'sha256',
            event['body-json']['password'],
            DYN_CONF['MASTER_SALT'],
            10000)
        hashed_password = binascii.hexlify(binary_hash)

        #compare results
        if hashed_password == DYN_CONF['MASTER_PASSWORD']:
            #generate token
            now_time = time.time()
            end_time = time.time() + 31104000
            claims = {
                'exp' : end_time,
                'nbf' : now_time,
                'iss' : 'medpass-aws',
                'aud' : 'webclient',
                'iat' : now_time,
                'type' : 'MASTER',
                'id' : 'MASTER'
            }

            jwe_token = jose.encrypt(claims, {'k':PUBLIC_KEY}, enc='A256CBC-HS512')
            auth_token = jose.serialize_compact(jwe_token)

            output = {
                'status':'success',
                'Authorization': auth_token,
                'type':'MASTER'
            }
        else:
            output = {'status':'error', 'message':'failed login'}

    except:
        LOGGER.error(traceback.print_exc())
        output = {'status':'error', 'message':'failed login'}

    return output


def login(event, context):
    """AWS_LAMBDA:auth_login_jwt
    Authenticate a valid email/password combination.

    :param email: User identification email.
    :type email: str.
    :param password: User password.
    :type password: str.
    :returns: str -- Authentication token used for API calls.

    """

    try:
        #request user data (password, active_status, salt and id) from user services
        login_data = 'email' in event['body-json'] and {
            'email': event['body-json']['email']} or {
                'cpf': event['body-json']['cpf']}

        response = LAMBDA_CLIENT.invoke(
            FunctionName='arn:aws:lambda:us-west-2:566614558620:function:user_get_credentials:' + ENVIRONMENT,
            Qualifier=ENVIRONMENT,
            InvocationType='RequestResponse',
            Payload=json.dumps(login_data),
            LogType='None'
        )

        payload = json.loads(response['Payload'].read())
        if response['StatusCode'] == 200 and payload['status'] == 'success':
            #if the user provided a captcha verify it works
            approved_captcha = False
            if 'g-captcha-response' in event['body-json'] and payload['failed_login_attempts'] >= 3:
                #validate recaptcha
                google_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
                    'secret':'6LdZNSgUAAAAAE8caj0ckJluAdJ3mGPHrE6kZW_n',
                    'response':event['body-json']['g-captcha-response'],
                    'remoteip':event['source-ip']
                }).json()
                approved_captcha = google_response['success']

            #verify that the user is not locked or did provide a captcha
            if payload['failed_login_attempts'] < 3 or approved_captcha:
                #generate password hash for comparison, a slow hash with multiple iterations is used to difficult attacks
                binary_hash = hashlib.pbkdf2_hmac(
                    'sha256',
                    event['body-json']['password'],
                    payload['salt'],
                    10000)
                hashed_password = binascii.hexlify(binary_hash)

                if 'token_annonymous' in event['body-json']:
                    annonymous_login = event['body-json']['token_annonymous'] == payload['token_annonymous'] and\
                                       True or False
                else:
                    annonymous_login = False

                #compare results and verify if user is active
                if (hashed_password == payload['password'] and payload['active']) or annonymous_login:

                    #clear old password reset tokens
                    USER_TABLE.update_item(
                        Key={'user_id':payload['user_id']},
                        UpdateExpression='SET password_token=:password_token, failed_login_attempts=:failed_login_attempts',
                        ExpressionAttributeValues={
                            ':password_token':{},
                            ':failed_login_attempts':0
                        }
                    )

                    #generate token
                    now_time = time.time()
                    end_time = time.time() + 31104000
                    claims = {
                        'exp' : end_time,
                        'nbf' : now_time,
                        'iss' : 'medpass-aws',
                        'aud' : 'webclient',
                        'iat' : now_time,
                        'type' : payload['type'],
                        'id' : payload['user_id']
                    }

                    jwe_token = jose.encrypt(claims, {'k':PUBLIC_KEY}, enc='A256CBC-HS512')
                    auth_token = jose.serialize_compact(jwe_token)

                    output = {
                        'status':'success',
                        'Authorization': auth_token,
                        'type':payload['type']
                    }

                    #profile dependent information
                    if 'profile_url' in payload:
                        output['profile_url'] = payload['profile_url']

                    #type dependent information
                    if payload['type'] == 'USER':
                        pendencies_response = REPORT_TABLE.get_item(
                            Key={'user_id':payload['user_id']},
                            ProjectionExpression='pendencies')
                        if 'Item' in pendencies_response:
                            output['pendencies'] = False
                        else:
                            output['pendencies'] = True
                    elif payload['type'] == 'PRE-MEDIC':
                        #warn user if data is being revisited
                        user_response = USER_TABLE.get_item(
                            Key={'user_id':payload['user_id']},
                            ProjectionExpression='profile')['Item']
                        if 'profile' in user_response:
                            output['sent'] = True
                        else:
                            output['sent'] = False
                        output['pendencies'] = True
                    elif payload['type'] == 'MEDIC':
                        output['pendencies'] = False


                else:
                    #include a failed login attempt to user
                    USER_TABLE.update_item(
                        Key={'user_id':payload['user_id']},
                        UpdateExpression='ADD failed_login_attempts :one',
                        ExpressionAttributeValues={
                            ':one':1
                        }
                    )
                    LOGGER.info('Incorrect login attempt at email: "' + event['body-json']['email'] + '".')
                    output = {'status':'error', 'message':'failed login'}
            else:
                LOGGER.info('Locked out user login attempt at email: "' + event['body-json']['email'] + '"')
                output = {'status':'captcha', 'message':'locked out user need to validate captcha'}
        else:
            LOGGER.error("Failed to request user credential." + payload['message'])
            output = {'status':'error', 'message':'failed login'}

    except:
        LOGGER.error(traceback.print_exc())
        output = {'status':'error', 'message':'failed login'}

    return output

def internal_auth_registration(event, context):
    """AWS_LAMBDA:auth_registration_jwt
    Generate a valid token for registration purposes.

    :param rt: Registration token.
    :type rt: str.
    :returns: str -- Authentication token used for API calls.

    """

    #generate token
    now_time = time.time()
    end_time = time.time() + 31104000
    claims = {
        'exp' : end_time,
        'nbf' : now_time,
        'iss' : 'medpass-aws',
        'aud' : 'webclient',
        'iat' : now_time,
        'type' : 'REGISTRATION',
        'id' : event['rt']
    }

    jwe_token = jose.encrypt(claims, {'k':PUBLIC_KEY}, enc='A256CBC-HS512')
    auth_token = jose.serialize_compact(jwe_token)
    output = {'Authorization': auth_token}
    return output


def internal_auth_temporary(event, context):
    """AWS_LAMBDA:auth_temporary_jwt
    Generate a valid token for temporary access.

    :param tt: Registration token.
    :type tt: str.
    :returns: str -- Authentication token used for API calls.

    """

    #generate token
    now_time = time.time()
    end_time = time.time() + 31104000
    claims = {
        'exp' : end_time,
        'nbf' : now_time,
        'iss' : 'medpass-aws',
        'aud' : 'webclient',
        'iat' : now_time,
        'type' : 'TEMPORARY',
        'id' : event['user_id']
    }

    jwe_token = jose.encrypt(claims, {'k':PUBLIC_KEY}, enc='A256CBC-HS512')
    auth_token = jose.serialize_compact(jwe_token)
    output = {'Authorization': auth_token}
    return output


def lambda_handler(event, context):
    """AWS_LAMBDA:auth_gateway
    Validate the incoming token and produce the principal user identifier
    associated with the token. Decoding a JWT token inline.

    :param authorizationToken: Authentication token.
    :type authorizationToken: str.
    :param methodArn: Contains information on api_gateway_arn and aws_account_id.
    :type methodArn: str.
    :returns: AuthPolicy -- Policy object with access permissions.

    """

    try:
        #retrieve claims from token
        jwt_token = jose.decrypt(jose.deserialize_compact(event['authorizationToken']), {'k':PRIVATE_KEY})
    except jose.Error as jwt_exception:
        LOGGER.error(jwt_exception)
        raise Exception('Unauthorized')

    now_time = time.time()
    if now_time - 31104000 > jwt_token.claims['iat'] or\
    jwt_token.claims['iss'] != 'medpass-aws' or\
    jwt_token.claims['aud'] != 'webclient' or\
    jwt_token.claims['type'] not in ['REGISTRATION', 'TEMPORARY', 'USER','PRE-MEDIC', 'MEDIC']:
        LOGGER.error('Tampered token (iss:' + jwt_token.claims['iss'] + ', aud:' + jwt_token.claims['aud'] + ', type:' + jwt_token.claims['type'] + ').')
        raise Exception('Unauthorized')

    #create policy
    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    aws_account_id = tmp[4]
    LOGGER.info(jwt_token.claims['id'])
    principal_id = jwt_token.claims['id']
    policy = AuthPolicy(principal_id, aws_account_id)

    #adjust policy to user profile
    if jwt_token.claims['type'] == 'MASTER':
        policy.allowMethod(HttpVerb.ALL, '/admin/user')
    
    if jwt_token.claims['type'] == 'ADMIN':
        policy.allowMethod(HttpVerb.ALL, '/admin/laboratory/user')
        policy.allowMethod(HttpVerb.ALL, '/admin/enterprise/user')

    if jwt_token.claims['type'] == 'REGISTRATION':
        policy.allowMethod(HttpVerb.POST, '/user')

    elif jwt_token.claims['type'] == 'TEMPORARY':
        policy.allowMethod(HttpVerb.OPTIONS, '/medic/temporary')
        policy.allowMethod(HttpVerb.GET, '/medic/temporary')

    elif jwt_token.claims['type'] == 'PRE-MEDIC':
        policy.allowMethod(HttpVerb.OPTIONS, '/medic')
        policy.allowMethod(HttpVerb.PUT, '/medic')

    elif jwt_token.claims['type'] == 'USER' or jwt_token.claims['type'] == 'MEDIC':
        if jwt_token.claims['type'] == 'MEDIC':
            policy.allowMethod(HttpVerb.POST, '/medic')
            policy.allowMethod(HttpVerb.PUT, '/medic')
            policy.allowMethod(HttpVerb.OPTIONS, '/medic')

            policy.allowMethod(HttpVerb.GET, '/medic/patient')
            policy.allowMethod(HttpVerb.POST, '/medic/patient')
            policy.allowMethod(HttpVerb.OPTIONS, '/medic/patient')

            policy.allowMethod(HttpVerb.ALL, '/medic/calendar')

            policy.allowMethod(HttpVerb.GET, '/medic/dashboard')
            policy.allowMethod(HttpVerb.OPTIONS, '/medic/dashboard')

        policy.allowMethod(HttpVerb.GET, '/user')
        policy.allowMethod(HttpVerb.PUT, '/user')
        policy.allowMethod(HttpVerb.OPTIONS, '/user')
        policy.allowMethod(HttpVerb.POST, '/user/pendencies')
        policy.allowMethod(HttpVerb.OPTIONS, '/user/pendencies')
        policy.allowMethod(HttpVerb.POST, '/user/medics')
        policy.allowMethod(HttpVerb.OPTIONS, '/user/medics')
        policy.allowMethod(HttpVerb.ALL, '/user/goals')

        policy.allowMethod(HttpVerb.POST, '/question')
        policy.allowMethod(HttpVerb.OPTIONS, '/question')
        policy.allowMethod(HttpVerb.POST, '/question/risk')
        policy.allowMethod(HttpVerb.OPTIONS, '/question/risk')
        policy.allowMethod(HttpVerb.POST, '/question/index')
        policy.allowMethod(HttpVerb.OPTIONS, '/question/index')
        policy.allowMethod(HttpVerb.POST, '/question/assistance')
        policy.allowMethod(HttpVerb.OPTIONS, '/question/assistance')
        policy.allowMethod(HttpVerb.POST, '/question/historic')
        policy.allowMethod(HttpVerb.OPTIONS, '/question/historic')

        policy.allowMethod(HttpVerb.POST, '/registration')
        policy.allowMethod(HttpVerb.OPTIONS, '/registration')

        policy.allowMethod(HttpVerb.ALL, '/report')
        policy.allowMethod(HttpVerb.OPTIONS, '/report/pendencies')
        policy.allowMethod(HttpVerb.POST, '/report/pendencies')
        policy.allowMethod(HttpVerb.OPTIONS, '/report/risk')
        policy.allowMethod(HttpVerb.POST, '/report/risk')
        policy.allowMethod(HttpVerb.OPTIONS, '/report/share')
        policy.allowMethod(HttpVerb.POST, '/report/share')
        policy.allowMethod(HttpVerb.GET, '/report/share')
        policy.allowMethod(HttpVerb.DELETE, '/report/share')

        policy.allowMethod(HttpVerb.OPTIONS, '/dashboard')
        policy.allowMethod(HttpVerb.POST, '/dashboard')

        policy.allowMethod(HttpVerb.OPTIONS, '/forms')
        policy.allowMethod(HttpVerb.OPTIONS, '/forms/city')
        policy.allowMethod(HttpVerb.POST, '/forms/city')

        policy.allowMethod(HttpVerb.ALL, '/assistance')
        policy.allowMethod(HttpVerb.ALL, '/historic')

        policy.allowMethod(HttpVerb.ALL, '/web')

        policy.allowMethod(HttpVerb.OPTIONS, '/mail')
        policy.allowMethod(HttpVerb.OPTIONS, '/mail/faq')
        policy.allowMethod(HttpVerb.POST, '/mail/faq')

    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gateway_arn_tmp[1]

    # Build the policy and exit the function using return
    output = policy.build()
    return output


class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    """Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    """

    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
