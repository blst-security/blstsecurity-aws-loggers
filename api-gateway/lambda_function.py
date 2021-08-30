import json
import boto3
from datetime import datetime, timedelta
import time
import requests
import random

logs = boto3.client('logs')
gateways = boto3.client('apigateway')
events = boto3.client('events')
lambdas = boto3.client('lambda')

def put_rule(name):
    rule_name = name + '-rule'
    lambda_details = lambdas.get_function(FunctionName=name)
    lambda_arn = ''
    lambda_role = ''
    if 'Configuration' in lambda_details:
        lambda_arn = lambda_details['Configuration']['FunctionArn']
        lambda_role = lambda_details['Configuration']['Role']
    if lambda_arn != '':
        response = events.list_rule_names_by_target(
            TargetArn=lambda_arn
        )
        if not len(response['RuleNames']):
            rule_arn = events.put_rule(
                Name=rule_name,
                ScheduleExpression='rate(10 minutes)',
                State='ENABLED',
                Description='rule for running blstsecurity logs'
            )
            events.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Arn': lambda_arn,
                        'Id': 'blstsecurity_logs_event_target',
                    }
                ]
            )
            lambdas.add_permission(
                FunctionName=name,
                StatementId='AWS_Event' + str(random.randint(100000,999999)),
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=rule_arn['RuleArn']
            )
    
def get_timestamp(data):
    return data[0]['value']
     
def get_id(data):
    return data[1]['value'][1:36]
    
def get_logs_from_group(log_group, start_time, query):
    date_start_time = datetime.fromtimestamp(start_time)
    start_query_response = logs.start_query(
        logGroupName=log_group,
        startTime=start_time - 30,
        endTime=start_time + 600,
        queryString=query,
    )
    query_id = start_query_response['queryId']
    response = None
    while response == None or response['status'] == 'Running':
        time.sleep(1)
        response = logs.get_query_results(
            queryId=query_id
        )
    data=[]
    response['results'].sort(key=lambda data: (get_id(data), get_timestamp(data)))
    prev_stream_key = ''
    stream_arr = []
    add_stream = False
    for stream in response['results']:
        stream_key = stream[1]['value'][1:36]
        log_time = stream[0]['value']
        stream_message = stream[1]['value'][39:]
        date_log_time = datetime.strptime(log_time, '%Y-%m-%d %H:%M:%S.%f')
        if date_log_time > date_start_time and 'response body after transformations:' in stream_message[0:85]:
            add_stream = True
        if prev_stream_key != '' and stream_key != prev_stream_key:
            if add_stream and len(stream_arr):
                data.append(stream_arr)
            stream_arr = []
            add_stream = False
        stream_arr.append({"time":log_time,"message":stream_message,"id":stream_key})
        prev_stream_key = stream_key
    if add_stream:
        data.append(stream_arr)
    return {"log_group_name":log_group,"data":data}

def lambda_handler(event, context):
    start_time = int((datetime.today() - timedelta(minutes=13)).timestamp())
    query = "fields @timestamp, @message"
    put_rule('blstsecurity-logs')
    for log_group in logs.describe_log_groups(logGroupNamePrefix='API-Gateway-Execution-Logs_')['logGroups']:
        api_log_group = get_logs_from_group(log_group['logGroupName'], start_time, query)
        if 'data' in api_log_group and len(api_log_group['data']):
            requests.post('https://z2yh3zbaw1.execute-api.eu-central-1.amazonaws.com/poc/send', data = json.dumps(api_log_group))
        
    return 'success'
