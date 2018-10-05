import json
import os
import sys
import shlex
import subprocess

#### Load Option File ####
with open('option.json') as f:
    data = json.load(f)

#### Options Veribles ####
PriIP = data["Primary"]["IP"]
PriUser = data["Primary"]["User"]
PriPass = data["Primary"]["Pass"]
PriLoc = data["Primary"]["Loc"]

PriIP = data["Standby"]["IP"]
PriUser = data["Standby"]["User"]
PriPass = data["Standby"]["Pass"]
PriLoc = data["Standby"]["Loc"]

#### Check Servers can be reached ####

#### Check Servers can be logged into ####

#### Check File system ####

#### Move files ####
