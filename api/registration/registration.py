"""
registration.py: encapsulates all lambda functions related to user registration
"""
__author__ = "Rafael Pelegrini Domingues"
__copyright__ = "Copyright 2018, Bain & Co"

#base imports
import os
import re
import logging
import json
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

#utilities imports
import boto3
from botocore.exceptions import ClientError

# local imports

#get running environment
ENVIRONMENT = os.environ['ENV']

#common resources for multiple lambda requests
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
LAMBDA_CLIENT = boto3.client('lambda')

#configure access to lambda configurations
#DYNAMO_DB = boto3.resource('dynamodb', region_name='sa-east-1')
SES_CLIENT = boto3.client('ses', region_name='us-west-2')
#USER_TABLE = DYNAMO_DB.Table('user_' + ENVIRONMENT)
#R_TOKEN_TABLE = DYNAMO_DB.Table('r_token_' + ENVIRONMENT)

SENDER = "Training On-Demand <registration@trainingondemand.io>"

def register(event, context):
    """AWS_LAMBDA:register
    Register a valid email address and send an invitation email.

    :param email: User email.
    :type email: str.
    :returns: str -- Authentication token used for API calls.

    """
    try:
        #check if email is registered at bain
        if re.match(r'^[a-zA-Z0-9_+&*-\.]*?@bain\.com$', event['body-json']['email']):

            #check if user is already registered
            if 1 == 1:
                #create deactivated user
                #TODO

                #generate token
                #TODO

                message = MIMEMultipart('mixed')
                message['Subject'] = 'Bem-vindo ao Training On-Demand!'
                message['From'] = SENDER
                message['To'] = event['body-json']['email']

                message_body = MIMEMultipart('alternative')
                text_body = MIMEText('Olar'.encode('utf-8'), 'plain', 'utf-8')
                html_body = MIMEText('Olaros'.encode('utf-8'), 'plain', 'utf-8')
                message_body.attach(text_body)
                message_body.attach(html_body)
                message.attach(message_body)

                #send email
                response = SES_CLIENT.send_raw_email(
                    Source=SENDER,
                    Destinations=[
                        event['body-json']['email']
                    ],
                    RawMessage={
                        'Data':message.as_string()
                    }
                )

                output = {
                    'status':'success',
                    'message':'registration completed'
                }
            else:
                output = {'status':'error', 'message':'failed registration'}
        else:
            output = {'status':'error', 'message':'invalid email'}

    except ClientError as e:
        LOGGER.error(e.response['Error']['Message'])
        output = {'status':'error', 'message':'failed registration'}
    except:
        LOGGER.error(traceback.print_exc())
        output = {'status':'error', 'message':'failed registration'}

    return output
