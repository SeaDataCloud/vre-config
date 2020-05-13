#!/usr/bin/python

#===================================================================
# A script that generates a json file with the docker health status
# of the running containers in the server
# 
# author: themis@grnet.gr
# GRNET
#===================================================================

import json
import sys
import argparse
import os
import subprocess
from datetime import date
import time

result = subprocess.Popen(['docker','ps', '--format', '{{.Names}}' ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

output=[]
ContainerNames = []
output_buf = result.stdout.readline()
i=0
while output_buf:
    output_buf = result.stdout.readline()

    if output_buf.split("\n")[0]!="":
       ContainerNames.append(output_buf.split("\n")[0])

current = 0
health_statuses = {}
while current < len(ContainerNames):
     containerNameToCheck = ContainerNames[current]
     command = "docker inspect " + containerNameToCheck +" | jq '.[].State.Health.Status'"
     result = subprocess.check_output(command, shell=True)
     health_statuses[containerNameToCheck] = result.split("\n")[0]
     current += 1

t = time.localtime()
today = date.today()
current_date = today.strftime("%d/%m/%Y")
current_time = time.strftime("%H:%M:%S", t)
health_statuses['time'] = current_date +" "+ current_time


jsonfile = "vre-health.json"
with open(jsonfile, 'w') as outfile:
    json.dump(health_statuses, outfile )

src = "./"+jsonfile
dst = "/var/vre-health/"+jsonfile
from shutil import copyfile
copyfile(src, dst)

