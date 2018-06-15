import boto3
import csv
import urllib2
import urllib
import json

def topic_loader():
    #client = boto3.client('dynamodb')
    dynamodb = boto3.resource('dynamodb', region_name='sa-east-1')
    table = dynamodb.Table('topic')

    with open('topics.csv') as csv_file:
        reader = csv.DictReader(csv_file, delimiter=";")
        for row in reader:
            table.put_item(
                Item = {
                    'name':row['name'],
                    'type':row['type'],
                    'short_name':row['short_name'],
                    'description':'TODO'
                }
            )

        csv_file.close()
    return


if __name__ == "__main__":
    topic_loader()