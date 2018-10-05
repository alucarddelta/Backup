#!/bin/python

import json
import os
import sys
import shlex
import subprocess
import base64
import argparse
import logging
import paramiko
from Crypto.Cipher import AES

#### Logging ####

logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logging.basicConfig(filename='log.txt', level=logging.WARNING, format='%(asctime)s | %(levelname)s | %(message)s')
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

#### Arg Check ####

MASTER_KEY="86F317C63921B3F514D258D5F30AC640B777451D0C6A1AA1B1DC0C23C9A5F07F"

parser = argparse.ArgumentParser(prog='Backup Check', description='Backup Check')
parser.add_argument('-p', help='Password to be saved', dest="password")
args = parser.parse_args()

def encrypt_val(clear_text):
    enc_secret = AES.new(MASTER_KEY[:32])
    tag_string = (str(clear_text) + (AES.block_size - len(str(clear_text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(enc_secret.encrypt(tag_string))
    exit(2)
    return cipher_text

if args.password:
    ctpassword = args.password
    outputpass = "Password generated " + encrypt_val(ctpassword).decode("utf-8")
    print(outputpass)
    logging.info(outputpass)
    exit(0)

#### Load Option File ####

with open('option.json') as f:
    data = json.load(f)

#### Options Veribles ####

PriIP = data["Primary"]["IP"]
PriUser = data["Primary"]["User"]
PriLoc = data["Primary"]["Loc"]

StbIP = data["Standby"]["IP"]
StbUser = data["Standby"]["User"]
StbLoc = data["Standby"]["Loc"]

#### Clear Text Check ####

CT = data["Setting"]["ClearTextPass"]
def CTcheck(x):
    if x in ("True", "False"):
        pass
    else:
        print("Config input error | Check Clear Text options are True or False.")
        exit(2)
    return
CTcheck(CT)

def decrypt_val(cipher_text):
    dec_secret = AES.new(MASTER_KEY[:32])
    raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
    clear_val = raw_decrypted.decode().rstrip("\0")
    return clear_val

    #.decode("utf-8")

if CT == "True":
    PriPass = data["Primary"]["Pass"]
    StbPass = data["Standby"]["Pass"]
else:
    EnPriPass = data["Primary"]["Pass"]
    PriPass = decrypt_val(EnPriPass)
    EnStbPass = data["Standby"]["Pass"]
    StbPass = decrypt_val(EnStbPass)

#### Check Servers can be reached ####

def IPcheck(SIP,ser):
    IPcommand = shlex.split("ping -c 1 " + SIP)
    IPprocess = subprocess.Popen(IPcommand, stdout=subprocess.PIPE)
    output, err = IPprocess.communicate()
    logging.info(output)

    if IPprocess.poll() == 0:
        IPstatus = ser + "PINGOK"
    else:
        IPstatus = ser + "PINGFAIL"
    return(IPstatus)

#### Check Servers can be logged into ####

def SSHCheck(SIP,SUN,SPASS,ser):
    try:
        SSHclient=paramiko.SSHClient()
        SSHclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSHclient.connect(SIP, username=SUN, password=SPASS, timeout= 1)
        SSHclient.close()
        SSHstatus = ser + "SSHCOK"
    except Exception as e:
        SSHstatus = ser + "SSHCFAIL"
    return(SSHstatus)

#### Check File system ####

#def check
#ssh = subprocess.Popen(["ssh", "%s" % HOST, COMMAND],
#                       shell=False,
#                       stdout=subprocess.PIPE,
#                       stderr=subprocess.PIPE)
#result = ssh.stdout.readlines()
#if result == []:
#    error = ssh.stderr.readlines()
#    print >>sys.stderr, "ERROR: %s" % error
#else:
#    print result

#### Stage 1 Main ####

PriIPCS = IPcheck(PriIP, "Pri")
StbIPCS = IPcheck(StbIP, "Stb")

if PriIPCS == "PriPINGFAIL" and StbIPCS == "StbPINGFAIL":
    serverstatus = "BothPingsFail"
    print(serverstatus)
    exit(2)

if PriIPCS == "PriPINGOK" and StbIPCS == "StbPINGOK":
    serverstatus = "SerPingsOK"
    print(serverstatus)
else:
    if PriIPCS == "PriPINGFAIL":
        serverstatus = "PriPingsFail"
        print(serverstatus)
        exit(1)
    else:
        serverstatus = "StbPingsFail"
        print(serverstatus)
        exit(1)

#### Stage 2 Main ####

PriCOMMAND = SSHCheck(PriIP,PriUser,PriPass, "Pri")
StbCOMMAND = SSHCheck(StbIP,StbUser,StbPass, "Stb")

if PriCOMMAND == "PriSSHCFAIL" and StbCOMMAND == "StbSSHCFAIL":
    serverconnstatus = "BothSSHFail"
    print(serverconnstatus)
    exit(2)

if PriCOMMAND == "PriSSHCOK" and StbCOMMAND == "StbSSHCOK":
    serverconnstatus = "SerSSHOK"
    print(serverconnstatus)
    exit(0)
else:
    if PriCOMMAND == "PriSSHCFAIL":
        serverconnstatus = "PriSSHFail"
        print(serverconnstatus)
        exit(1)
    else:
        serverconnstatus = "StbSSHFail"
        print(serverconnstatus)
        exit(1)
