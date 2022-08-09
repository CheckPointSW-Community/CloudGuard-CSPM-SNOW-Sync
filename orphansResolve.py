#!/usr/bin/env python3

from asyncio.windows_events import NULL
from sre_constants import ANY
from time import strftime
import os
from urllib.parse import urlencode
from pysnc import ServiceNowClient, ServiceNowOAuth2
import requests
import math
from datetime import datetime, timedelta
from dateutil.relativedelta import *
import json
from requests.auth import HTTPBasicAuth

# Chkp API key
chkpapikey = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Chkp API secret
chkpapisecret = "xxxxxxxxxxxxxxxxxxxxxxxx"

#SNOW LOGIN User
snowAdmin = "admin"
#SNOW LOGIN PWD
snowAdmPwd = "@@@@@@@@@@@@"

#SNOW Instance
GetsnowInstance = "vvvvvvvv"

#Get RulesetID
RulesetID="-11"

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
  myresults = [];
  payload={
    'filter': {
        'fields': [
            {
                'name': 'bundleId',
                'value': str(RulesetID)
            }
        ]
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
                myresults.append(z['findingKey']);
    payload={ 
        'filter': {
            'fields': [
               {
                    'name': 'bundleId',
                    'value': str(RulesetID)
               }
            ]
        },
        'pageSize': '20',
        'dataSource': 'Finding',
        'searchAfter':[ str(searchafter) ]
    }
  r = requests.post( 'https://api.dome9.com/v2/Compliance/Finding/search', json=payload, headers=headers, auth=(apiKey, apiSecret));
#  return r.json();
  return myresults;

def fetchD9SNOWIncd(snowInstance, snowUser, snowPasswd): 
    myincid=[]
    searchstr = urlencode({'sysparm_limit': 1 })
    murl = "https://"+snowInstance+".service-now.com/api/now/table/x_chpst_dome9_compliance_incident?"+searchstr
    headers = {
        "accept": "application/json;charset=utf-8",
        "Content-Type": "application/json",
    }
    resp = requests.get(murl, auth=(snowUser, snowPasswd), headers=headers)
    if len(resp.json()) != 0:
       for kincid, vincid in resp.json().items():
           if len(vincid) != 0:
                for g in vincid:
                    thisincid={
                        "incident": g['incident']['value'],
                        "alert_id": g['alert_id']
                    }
                    myincid.append(thisincid)
    return(myincid);

# Check for HTTP codes other than 200
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        exit()
    

def fetchSNOWIncdAct(snowIncident, snowInstance, snowUser, snowPasswd):
    urlIncd = 'https://'+snowInstance+'.service-now.com/api/now/table/incident/'+snowIncident
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    resp = requests.get(urlIncd, auth=(snowUser, snowPasswd), headers=headers)
    
    for kincid, vincid in resp.json().items():
        if(vincid['state'] != "6" and vincid['state'] != "7"):
                ### then update active record to closed else skip
                #myincid.append(vincid[0]['incident']['link'])
                resolveIncident(urlIncd, snowUser, snowPasswd);
# Check for HTTP codes other than 200
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        exit()


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
    recdata='{"state":"6", "category":"application","closed_at": "'+nowtime+'","close_code":"Solved (Permanently)","subcategory":"Settings/Preferences","close_notes":"Automatically closed via integration as compliance incident was detected as resolved","caused_by":"Configured/Reconfigured","problem_id":"No"}'
    resp = requests.patch(snowIncident, auth=(snowUser, snowPasswd), headers=headers, data=recdata)
    print(snowIncident);
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        return 1 ;
    return 0 ;
  
 
try:
 
    SNOWincidLnk = fetchD9SNOWIncd( GetsnowInstance, snowAdmin, snowAdmPwd);
    SNOWalerts = []
    absent = []
    tbd = []
    for SNAlert in SNOWincidLnk:
        SNOWalerts.append(SNAlert['alert_id'])
    openfindings = chkpfindings(chkpapikey,chkpapisecret);
    absent = set(SNOWalerts).difference(set(openfindings));

    for inx, alertID in enumerate(absent):
        for incident, xalert in enumerate(SNOWincidLnk):
            if alertID == xalert['alert_id']:
                tbd.append(xalert['incident']);
#    print(tbd)
    for finding in tbd:
        fetchSNOWIncdAct(finding, GetsnowInstance, snowAdmin, snowAdmPwd)
    exit()

except Exception as e:
    print("Error.", str(e))