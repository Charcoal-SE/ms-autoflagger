from __future__ import print_function
import boto3
import os
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import sys
import time

client = boto3.client('dynamodb')

def lambda_handler(event, context):
    if event["resource"] == "/auth":
        return run_auth(event)
    elif event["resource"] == "/auth/complete":
        return completed_auth(event)
    elif event["resource"] == "/auth/confirm":
        return confirm_auth(event)
    elif event["resource"] == "/autoflag":
        return cast_flags(event)
    elif event["resource"] == "/autoflag/options":
        return flag_options(event)
    elif event["resource"] == "/load_tokens":
        return load_tokens(event)
    elif event["resource"] == "/invalidate_tokens":
        return invalidate_tokens(event)
    # elif event["resource"] == "/verify_account_id":
    #     return account_ids(event)
    else:
        return {
            "isBase64Encoded": False,
            "statusCode": 404,
            "headers": {},
            "body": "{}"
        }

def confirm_auth(event):
    params = event["queryStringParameters"]
    acct_id = params["account_id"]
    state = params["state"]
    i = client.get_item(TableName=os.environ['TABLE_NAME'],
                    Key={"account_id": {"N":acct_id}})
    res = "state" in i["Item"] and state == i["Item"]["state"]["S"]
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {},
        "body": json.dumps({"token_exists": res})
    }

def load_tokens(event):
    data = json.loads(event["body"])
    for user_info in data["tokens"]:
        access_token = user_info["access_token"]
        account_id = user_info["account_id"]
        item = {
            "account_id" : {
                "N" : str(account_id)
            },
            "access_token" : {
                "S" : access_token
            }
        }
        if "expiration_date" in user_info:
            item["expiration_date"] = { "N": str(int(user_info["expiration_date"])+int(time.time()))}
        client.put_item(TableName=os.environ['TABLE_NAME'],Item=item)
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {"Content-Type":"text/plain"},
        "body": "All tokens loaded!"
    }

def invalidate_tokens(event):
    params = event["queryStringParameters"]
    acct_id = params["account_id"]
    api_key = os.environ['API_KEY']
    i = client.get_item(TableName=os.environ['TABLE_NAME'],
                    Key={"account_id": {"N":acct_id}})
    token = i['Item']['access_token']['S']
    query_string = {
        'key': api_key
    }
    uri = "https://api.stackexchange.com/2.2/access-tokens/"+token+"/invalidate"
    r = requests.get(uri, data=query_string)
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {},
        "body": r.text
    }

def flag_options(event):
    params = event["queryStringParameters"]
    account_id = params["account_id"]
    api_key = os.environ['API_KEY']
    i = client.get_item(TableName=os.environ['TABLE_NAME'],
                    Key={"account_id": {"N":account_id}})
    if (not 'Item' in i) or (not "access_token" in i['Item']):
        return {
            "isBase64Encoded": False,
            "statusCode": 404,
            "headers": {},
            "body": json.dumps({'message': 'Could not find a token for that account'})
        }
    token = i['Item']['access_token']['S']
    if params["post_type"] in ["question", "answer"]:
        query_string = {
            'site': params['site'],
            'key': api_key,
            'access_token': token
        }
        uri = "https://api.stackexchange.com/2.2/"+params["post_type"]+"s/"+params["post_id"]+"/flags/options"
        r = requests.get(uri, data=query_string)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": r.text
        }
    else:
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": json.dumps({'message': "Invalid post type "+params["post_type"]+". Expected 'question' or 'answer'"})
        }

def cast_flags(event):
    params = event["queryStringParameters"]
    account_id = params["account_id"]
    api_key = os.environ['API_KEY']
    i = client.get_item(TableName=os.environ['TABLE_NAME'],
                    Key={"account_id": {"N":account_id}})
    if (not 'Item' in i) or (not "access_token" in i['Item']):
        return {
            "isBase64Encoded": False,
            "statusCode": 404,
            "headers": {},
            "body": json.dumps({'message': 'Could not find a token for that account'})
        }
    token = i['Item']['access_token']['S']
    if params["post_type"] in ["question", "answer"]:
        if "comment" in params:
            comment = params["comment"]
        else:
            comment = ''
        query_string = {
            'site': params['site'],
            'key': api_key,
            'access_token': token,
            'option_id': params['flag_option_id'],
            'comment': comment,
            'preview': 'false'
        }
        uri = "https://api.stackexchange.com/2.2/"+params["post_type"]+"s/"+params["post_id"]+"/flags/add"
        r = requests.post(uri, data=query_string)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": r.text
        }
    else:
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {"Content-Type":"text/plain"},
            "body": json.dumps({"message": "Invalid post type "+params["post_type"]+". Expected 'question' or 'answer'"})
        }

def completed_auth(event):
    client_id = os.environ['CLIENT_ID']
    client_secret = os.environ['CLIENT_SECRET']
    qsp = event["queryStringParameters"]
    if "error" in qsp:
        if "REDIRECT_URI" in os.environ:
            return {
                "isBase64Encoded": False,
                "statusCode": 302,
                "headers": {"Location":os.environ['REDIRECT_URI'] + "?error="+qsp["error"]+"&error_description="+qsp["error_description"]},
                "body": "SE OAuth Failed! Redirecting you..."
            }
        else:
            return {
                "isBase64Encoded": False,
                "statusCode": 200,
                "headers": {"Content-Type":"text/plain"},
                "body": "SE OAuth Failed :(\n" + r.text
            }
    code = qsp["code"]
    if "state" in qsp:
        state = qsp["state"]
    else:
        state = ""
    ctx = event["requestContext"]
    redirect_uri = "https://" + ctx["domainName"] + ctx["path"]
    r = requests.post("https://stackoverflow.com/oauth/access_token",
                        data={
                        "client_id": client_id,
                        "code": code,
                        "client_secret": client_secret,
                        "redirect_uri": redirect_uri
                        })
    if r.status_code == 200:
        print("Doing stuff")
        qs = parse_qs(r.text)
        access_token = qs["access_token"][0]
        if "expires" in qs:
            expires = qs["expires"][0]
        else:
            expires = ""
        api_key = os.environ['API_KEY']
        print("Request was sucessful. Pulling profile information...")
        me = requests.get("https://api.stackexchange.com/2.2/me/associated?filter=!ms3dUCONeu&key="+str(api_key)+"&access_token="+str(access_token)+"&pagesize=1&page=1")
        print("Recieved profile information")
        if "error_id" in me.json():
            print("Profile JSON returned error")
            return {
                "isBase64Encoded": False,
                "statusCode": 200,
                "headers": {"Content-Type":"text/plain"},
                "body": "SE OAuth Failed, API Issues!\n" + me.text + "\n" + "https://api.stackexchange.com/2.2/me/associated?filter=!ms3dUCONeu&key="+str(api_key)+"&access_token="+str(access_token[0])+"&pagesize=1&page=1"
            }
        else:
            print("Pulling profile JSON sucessful!")
            id = me.json()["items"][0]["account_id"]
            item = {
                "account_id" : {
                    "N" : str(id)
                },
                "access_token" : {
                    "S" : access_token
                },
                "state" : {
                    "S" : state
                }
            }
            print("Writing to DynamoDB")
            if expires != "":
                item["expiration_date"] = { "N" : str(int(expires)+int(time.time())) }
            client.put_item(TableName=os.environ['TABLE_NAME'],Item=item)
            print("Wrote to DynamoDB")
            if "REDIRECT_URI" in os.environ:
                return {
                    "isBase64Encoded": False,
                    "statusCode": 302,
                    "headers": {"Location":os.environ['REDIRECT_URI'] + "?state="+state},
                    "body": "SE OAuth Sucessful! Redirecting you..."
                }
            else:
                return {
                    "isBase64Encoded": False,
                    "statusCode": 200,
                    "headers": {"Content-Type":"text/plain"},
                    "body": "SE OAuth Sucessful!"
                }
    else:
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {"Content-Type":"text/plain"},
            "body": "SE OAuth Failed :(\n" + r.text
        }

def run_auth(event):
    client_id = os.environ['CLIENT_ID']
    ctx = event["requestContext"]
    if "state" in event["queryStringParameters"]:
        state = event["queryStringParameters"]["state"]
    else:
        state = ""
    redirect_uri = "https://" + ctx["domainName"] + ctx["path"] + "/complete"
    qstring = "?redirect_uri=" + redirect_uri + "&client_id=" + client_id + "&scope=write_access,no_expiry&state="+state
    return {
        "isBase64Encoded": False,
        "statusCode": 302,
        "headers": {"Location": "https://stackoverflow.com/oauth" + qstring},
        "body": "Redirecting you to Stack Exchange OAuth"
    }
