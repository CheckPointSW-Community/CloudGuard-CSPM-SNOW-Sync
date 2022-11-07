#!/usr/bin/env python3
#########################################################
###    Script to close Orphaned SNOW Incidents        ###
###    CB Currier <ccurrier@Checkpoint.com>           ###
###    Version: 1.0    Date: 8/3/2022                 ###
###    Updated: 11/07/22                              ###
###    TAGS: CSPM CHKP DOME9 WORKAROUND CLOUDALLIANCE ###
#########################################################
from asyncio.windows_events import NULL
from doctest import debug_script
from pickle import FALSE
from sre_constants import ANY
from time import strftime
import os
from urllib.parse import urlencode
from pysnc import ServiceNowClient, ServiceNowOAuth2
import requests
import math
from datetime import datetime, timedelta
from dateutil.relativedelta import *
import sys
from requests.auth import HTTPBasicAuth

# Chkp API key
chkpapikey = os.environ['CHKP_API_KEY']
# Chkp API secret
chkpapisecret = os.environ["CHKP_API_SEC"]
#SNOW LOGIN User
snowAdmin = os.environ["SNOW_AUT_USER"]
#SNOW LOGIN PWD
snowAdmPwd = os.environ["SNOW_AUT_U_PWD"]
#SNOW Instance
GetsnowInstance = os.environ["SNOWINST"]

#Print Debugging Info
debugIncd = True

#Report Only
reportOnly = False

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
    searchstr = urlencode({'sysparm_fields': 'incident,alert_id'})
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
                         "alert_id": g['alert_id']
#                        "incident": g['incident']['value'],
                    }
                    myincid.append(thisincid)
    return(myincid);

# Check for HTTP codes other than 200
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        exit()
    

def fetchSNOWIncdAct(snowIncident, snowInstance, snowUser, snowPasswd):
    #use SNOW sysparam_query to fetch only non 6& 7 records with the incident having correlation_id
    # correlation_id is the AlertId from the CSPM
    searchst = urlencode({'sysparm_query':'state!=6^state!=7','sysparm_fields':'sys_id','correlation_id': snowIncident})
    urlIncd = 'https://'+snowInstance+'.service-now.com/api/now/table/incident?'+searchst
    #correlation_id
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }
    resp = requests.get(urlIncd, auth=(snowUser, snowPasswd), headers=headers)
    
    for kincid, vincid in resp.json().items():
        for incd in vincid:
#        if(vincid['state'] != "6" and vincid['state'] != "7"):
                ### then update active record to closed else skip
                resincd = 'https://'+snowInstance+'.service-now.com/api/now/table/incident/'+incd['sys_id']
                if(reportOnly == False) and (debugIncd == False):
                    resolveIncident(resincd, snowUser, snowPasswd);
                else:
                    print(resincd);

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
    if resp.status_code != 200: 
        print("ERROR:");
        print('Status:', resp.status_code, 'Headers:', resp.headers, 'Error Response:',resp.json())
        return 1 ;
    return 0 ;
  
 
try:
 
    SNOWincidLnk = fetchD9SNOWIncd( GetsnowInstance, snowAdmin, snowAdmPwd);
    if(debugIncd == True):
        print("#############################")
        print("####      DEBUG          ####")
        print("####    D9 Incidents     ####")
        print("#############################")
        print("")
        print(SNOWincidLnk)
        print("#############################")

        
    SNOWalerts = []
    absent = []
    tbd = []
    for SNAlert in SNOWincidLnk:
        SNOWalerts.append(SNAlert['alert_id'])
    openfindings = chkpfindings(chkpapikey,chkpapisecret);
    absent = set(SNOWalerts).difference(set(openfindings));
    if(debugIncd == True):
        print("#############################")
        print("####      DEBUG          ####")
        print("####   SNOW Missing INCD ####")
        print("#############################")
        print("")
        print(absent)
        print("#############################")
        print("")
        print("#############################")
        print("####      DEBUG          ####")
        print("####   Open Missing INCD ####")
        print("#############################")
        print("")
        

    for xindx, finding in enumerate(absent):
        fetchSNOWIncdAct(finding, GetsnowInstance, snowAdmin, snowAdmPwd)
    exit()

except Exception as e:
    print("Error.", str(e))