#!/usr/bin/env python3

from asyncio.windows_events import NULL
from sre_constants import ANY
from time import strftime
from urllib.parse import urlencode
from pysnc import ServiceNowClient, ServiceNowOAuth2
import requests
import os
import math
import sys
import logging
from datetime import datetime, timedelta
from dateutil.relativedelta import *
import calendar
import json
from requests.auth import HTTPBasicAuth

# Chkp API key
chkpapikey = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Chkp API secret
chkpapisecret = "zzzzzzzzzzzzzzzzzzzzzzzz"

#SNOW API UserKey
GetsnowUser = "00000000000000000000000000000000"
#SNOW API PWD
GetsnowPasswd = "@@@@@@@@@@"

#SNOW LOGIN User
snowAdmin = "admin"
#SNOW LOGIN PWD
snowAdmPwd = "************"

#SNOW Instance
GetsnowInstance = "xxxxxxxx"


def chkpfindings(apiKey, apiSecret):
  ###########################
  ####    Get Findings    ###
  ####   from CSPM Chkp   ###
  ###########################
  searchurl = "https://api.dome9.com/v2/Compliance/Finding/search";
  headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
  }
  datecalcNow = datetime.now()
  datecalcLast = datecalcNow + relativedelta(months=-1)
  myresults = [];
  payload={
    'filter': {
        'fields': [
            {
                'name': 'acknowledged',
                'value': 'true'
            }
        ],
        'creationTime': {
            'from': datecalcLast.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            'to': datecalcNow.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        }
    },
    'pageSize': '20',
    'dataSource': 'Finding'
  }
  r = requests.post( 'https://api.dome9.com/v2/Compliance/Finding/search', json=payload, headers=headers, auth=(apiKey, apiSecret));
  pageresults = math.ceil(r.json().get("totalFindingsCount")/20);
  for i in range(0, pageresults, 1):
    print('.', end = '');
    searchafter = r.json().get("searchAfter");
    for x, y in r.json().items():
        if (x=="findings"):
            for z in y:
                myresults.append(json.dumps(z));
    payload={ 
        'filter': {
            'fields': [
               {
                    'name': 'acknowledged',
                    'value': 'true'
               }
            ],
            'creationTime': {
                'from': datecalcLast.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                'to': datecalcNow.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            }
        },
        'pageSize': '20',
        'dataSource': 'Finding',
        'searchAfter':[ str(searchafter) ]
    }
  r = requests.post( 'https://api.dome9.com/v2/Compliance/Finding/search', json=payload, headers=headers, auth=(apiKey, apiSecret));
#  return r.json();
  return json.dumps(myresults);

def resolveIncident(snowIncident, snowUser, snowPasswd):
  ###############################################################
  #### Take Incident URL & open it & set Status to resolved #####
  ###############################################################
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    nowDatecalc = datetime.now()
    nowtime=nowDatecalc.strftime("%Y-%m-%dT%H:%M:%S.%fZ");
    recdata='{"state":"7", "close_notes":"Acknowledged in CSPM Portal", "close_code":"Closed/Resolved By Caller", "resolved_at":"'+nowtime+'", "resolved_by":"CSPMPortal"}'
    resp = requests.patch(snowIncident, auth=(snowUser, snowPasswd), headers=headers, data=recdata)
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        return 1 ;
    return 0 ;
  

def fetchD9SNOWIncd(snowInstance, snowUser, snowPasswd, chkpId):   
    searchstr = urlencode({'sysparm_limit': 1})
    murl = "https://"+snowInstance+".service-now.com/api/now/table/x_chpst_dome9_compliance_incident?alert_id="+chkpId+"&"+searchstr
    headers = {
        "accept": "application/json;charset=utf-8",
        "Content-Type": "application/json",
    }
    resp = requests.get(murl, auth=(snowUser, snowPasswd), headers=headers)
    if len(resp.json()) != 0:
       for kincid, vincid in resp.json().items():
           if len(vincid) != 0:
             myincid=vincid[0]['incident']['link']
             return(myincid);

# Check for HTTP codes other than 200
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        exit()
    

def fetchSNOWIncdAct(snowUser, snowPasswd, incdLink):   
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    resp = requests.get(incdLink, auth=(snowUser, snowPasswd), headers=headers)
    for kincid, vincid in resp.json().items():
        if(vincid['active']=="true"):
                ### then update active record to closed else skip
                myincid=vincid[0]['incident']['link']
                print(myincid);
                resolveIncident(myincid, snowAdmin, snowAdmPwd);
# Check for HTTP codes other than 200
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        exit()

 
try:
    openfindings = json.loads(chkpfindings(chkpapikey,chkpapisecret));
    for finding in openfindings:
        thisfinding = json.loads(finding);
        SNOWincidLnk = fetchD9SNOWIncd( GetsnowInstance, snowAdmin, snowAdmPwd, thisfinding['findingKey']);
        if SNOWincidLnk:
            fetchSNOWIncdAct(snowAdmin, snowAdmPwd, SNOWincidLnk);
        SNOWincidLnk=NULL
except Exception as e:
    print("Error.", str(e))