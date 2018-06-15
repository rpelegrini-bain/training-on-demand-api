"""
registration.py: encapsulates all lambda functions related to user registration
"""
__author__ = "Rafael Pelegrini Domingues"
__copyright__ = "Copyright 2018, Bain & Co"

#base imports
import os
import re
import uuid
import logging
import json
import traceback
import time
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

#utilities imports
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# local imports

#get running environment
ENVIRONMENT = os.environ['ENV']

#common resources for multiple lambda requests
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
LAMBDA_CLIENT = boto3.client('lambda')

#configure access to aws resources
DYNAMO_DB = boto3.resource('dynamodb', region_name='sa-east-1')
SES_CLIENT = boto3.client('ses', region_name='us-west-2')
USER_TABLE = DYNAMO_DB.Table('user_' + ENVIRONMENT)
R_TOKEN_TABLE = DYNAMO_DB.Table('r_token_' + ENVIRONMENT)

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
        if re.match(r'^[a-zA-Z0-9_+&*-\.]*?\.[a-zA-Z0-9_+&*-\.]*?@bain\.com$', event['body-json']['email']):

            #check if user is already registered
            if 'Item' not in USER_TABLE.get_item(Key={'email':event['body-json']['email']}):
                
                #create deactivated user
                USER_TABLE.put_item(Item={
                    'email':event['body-json']['email'],
                    'name':event['body-json']['email'][:-9].replace('.', ' ').title(),
                    'type':'USER',
                    'active':False,
                    'trainer':[],
                    'trainee':[]
                })

                #generate token
                token_id = str(uuid.uuid4())
                R_TOKEN_TABLE.put_item(Item={
                    'id':token_id,
                    'creation':int(time.mktime(datetime.datetime.now().timetuple())),
                    'email':event['body-json']['email']
                })

                message = MIMEMultipart('mixed')
                message['Subject'] = 'Bem-vindo ao Training On-Demand!'
                message['From'] = SENDER
                message['To'] = event['body-json']['email']

                email_content = 'Olá, termine seu cadastro entrando no link:\nhttps://trainingondemand.io/register/check/' + token_id
                
                message_body = MIMEMultipart('alternative')
                text_body = MIMEText(email_content.encode('utf-8'), 'plain', 'utf-8')
                html_body = MIMEText(email_content.encode('utf-8'), 'plain', 'utf-8')
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
                LOGGER.info('Atempt to register existent user.')
                output = {'status':'success', 'message':'registration completed'}
        else:
            output = {'status':'error', 'message':'invalid email'}

    except ClientError as e:
        LOGGER.error(e.response['Error']['Message'])
        output = {'status':'error', 'message':'failed registration'}
    except:
        LOGGER.error(traceback.print_exc())
        output = {'status':'error', 'message':'failed registration'}

    return output
