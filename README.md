﻿# CloudGuard-CSPM-SNOW-Sync
Python Scripts to interact with Check Point CSPM (Dome9) API to pull reported incidents and perform updates to ServiceNow Incidents.

The AckClosed.py script collects all acknowledged events in the last month and closes the related incident. This is not "Standard and accepted" logic as generally acknowledging an alert is to state that the event has been reviewed. However this is a way to demonstrate a logical methodology for closing an incident.

The orphansResolve.py script pulls all incidents from the Dome9 data table, pulls all findings related to a particular rule and filters for any SNOW alerts not having a matching finding/alert. Then if the alert is not in a state of 6 or 7 the incident is resolved with relevant comments and codes updated.

1. Run `pip install -r requirements.txt`
2. Set the variables in SetEnvVars.ps1 for a Widows Powershell Environment.
3. Run relevant script

Author: <a href="mailto:ccurrier@checkpoint.com">CB Currier <ccurrier@checkpoint.com></a>

Date: 8/3/2022

TAGS: CSPM CHKP DOME9 WORKAROUND CLOUDALLIANCE

Updated: 8/10/22

