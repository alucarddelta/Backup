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

logformat = "%(asctime)s | %(levelname)s | %(message)s"                                                                     #LOGING FORMAT
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format=logformat)
logging.basicConfig(filename='log.txt', level=logging.INFO, format=logformat)
logging.basicConfig(filename='log.txt', level=logging.WARNING, format=logformat)
logging.basicConfig(filename='log.txt', level=logging.ERROR, format=logformat)
logging.basicConfig(filename='log.txt', level=logging.CRITICAL, format=logformat)

##################################################################################################################################################################
#logging.getLogger("paramiko").setLevel(logging.WARNING)                                                                    #COMMENT OUT TO DISABLE PARAMIKO DEBUG
##################################################################################################################################################################

#### Arg Check ####

MASTER_KEY="86F317C63921B3F514D258D5F30AC640B777451D0C6A1AA1B1DC0C23C9A5F07F"                                               #ENCRYPTION KEY

parser = argparse.ArgumentParser(prog='Backup Check', description='Backup Check')
parser.add_argument('-p', help='Password to be saved', dest="password")                                                     #PARSER FOR -P PASSWORD
parser.add_argument('-t', help='Transfer files is missmatch is found', dest='transfer')
args = parser.parse_args()

def encrypt_val(clear_text):                                                                                                #ENCRYPTER
    enc_secret = AES.new(MASTER_KEY[:32])
    tag_string = (str(clear_text) + (AES.block_size - len(str(clear_text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(enc_secret.encrypt(tag_string))
    return cipher_text

if args.password:                                                                                                           #CHECKS IF -P WAS USED. IF TRUE IT WILL RUN THE ENCRYPER ONLY. NO CHECK
    ctpassword = args.password
    outputpass = "Password generated: " + encrypt_val(ctpassword).decode("utf-8")
    print(outputpass)                                                                                                       #PRINTS PASSWORD
    logging.info(outputpass)                                                                                                #LOGS ENCRYTPED PASSWORD IN LOG. NOT THE CLEAR TEXT VERSION
    exit(0)                                                                                                                 #OK EXIT

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
    if x in ("True", "False"):                                                                                              #CHECKS FOR CORRECT INPUT IN OPTION FILE
        logging.info("Clear Text: " + CT)
    else:
        cterror = "Invalid Clear Text option | {} not a vailed input.".format(x)                                            #FAIL STATEMENT
        logging.error(cterror)
        print(cterror)
        exit(2)                                                                                                             #NAGIOS CRITICAL EXIT
    return

CTcheck(CT)

def decrypt_val(cipher_text):                                                                                               #DECRYPTER
    dec_secret = AES.new(MASTER_KEY[:32])
    raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
    clear_val = raw_decrypted.decode().rstrip("\0")
    return clear_val

if CT == "True":                                                                                                            #CHECKS IF DECRYPTER IS NEEDED
    PriPass = data["Primary"]["Pass"]
    StbPass = data["Standby"]["Pass"]
else:                                                                                                                       #SETS VALUES IF FALSE
    EnPriPass = data["Primary"]["Pass"]
    PriPass = decrypt_val(EnPriPass)
    EnStbPass = data["Standby"]["Pass"]
    StbPass = decrypt_val(EnStbPass)

#### Ping Check def ####

def IPcheck(SIP,ser):
    IPcommand = shlex.split("ping -c 1 " + SIP)                                                                             #SINGLE PING CHECK
    IPprocess = subprocess.Popen(IPcommand, stdout=subprocess.PIPE)
    output, err = IPprocess.communicate()
    output1 = output
    if IPprocess.poll() == 0:
        logging.info ("Ping to {} {} OK".format(ser, SIP))                                                                  #OK RESPONSE
    else:
        ipfail= "Ping to {} {} Failed.".format(ser, SIP)                                                                    #FAIL RESPONSE
        logging.error (ipfail)
        logging.debug (output1)
        print("{}".format(ipfail))                                                                            #MSG TO NAGIOS
        exit(2)                                                                                                             #NAGIOS CRITICAL EXIT
    return

#### SSH check Def ####

def SSHCheck(SIP,SUN,SPASS,ser):
    try:
        SSHclient=paramiko.SSHClient()
        SSHclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSHclient.connect(SIP, username=SUN, password=SPASS, timeout= 1)
        SSHclient.close()                                                                                                   #CLOSE CONNECTION TO ALLOW NEW CONNECTION TO BE MADE
        logging.info ("SSH Connection to {} {} OK".format(ser, SIP))
    except paramiko.AuthenticationException as e1:                                                                          #SSH AUTH FAIL MSG
        logging.critical ("SSH Authentication failed when connecting to {} {}".format(ser, SIP))
        logging.debug ("{0}".format(e1))
        print("SSH Failed to {} | SSH Authentication failed when connecting to {} {}".format(ser, ser, SIP))                #MSG TO NAGIOS
        exit(2)                                                                                                             #NAGIOS CRITICAL EXIT
    except Exception as e2:
        logging.error ("SSH Connection to {} {} Failed".format(ser, SIP))
        logging.debug ("{0}".format(e2))
        print("SSH Failed to {} | SSH Connection failed when connecting to {} {}".format(ser, ser, SIP))                    #MSG TO NAGIOS
        exit(2)                                                                                                             #NAGIOS CRITICAL EXIT
    return

#### DIR check Def ####

def DIRCheck(SIP,SUN,SPASS,ser,loc):
    SSH_COMMAND = "cd {} && ls -d */ | cut -f1 -d'/'".format(loc)
    try:
        SSHclient=paramiko.SSHClient()
        SSHclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSHclient.connect(SIP, username=SUN, password=SPASS, timeout= 1)
        ssh_stdin, ssh_stdout, ssh_stderr = SSHclient.exec_command(SSH_COMMAND)
        logging.info ("DIR Connection to {} {} OK".format(ser, SIP))
        DIRout = ssh_stdout.read()
        DIRLout = [y for y in (x.strip() for x in DIRout.splitlines()) if y]
        logging.info ("{} of folders found on {}".format(len(DIRLout), ser))
        SSHclient.close()                                                                                                   #CLOSE CONNECTION TO ALLOW NEW CONNECTION TO BE MADE
    except Exception as e:
        msg = "File Compare on {} {} Failed".format(ser, SIP)
        print (msg)                                                                                                         #MSG TO NAGIOS
        logging.error (msg)
        logging.debug ("{0}".format(e))
        exit(2)                                                                                                             #NAGIOS CRITIAL EXIT
    return (DIRout)

def checkDIR(pri,stb):
    a = set(pri)
    b = set(stb)
    c = list(b - a)
    d = list(a - b)
    e = len(c) + len(d)
    if c == [] and d != []:
        msg = "Files missing from Standby Server | {} files are missing. {}".format(len(d),d)                               #MSG FOR NAGIOS AND LOG
        print(msg)
        logging.warning(msg)
        exit(1)                                                                                                             #NAGIOS WARNING EXIT
    if c != [] and d == []:
        msg = "Files missing from Primary Server | {} files are missing. {}".format(len(c),c)                               #MSG FOR NAGIOS AND LOG
        print(msg)
        logging.warning(msg)
        exit(1)                                                                                                             #NAGIOS WARNING EXIT
    if c != [] and d != []:
        msg = "Files missing on Both Server | {} files are missing. {} from Primary. {} from Standby.".format(e,c,d)        #MSG FOR NAGIOS AND LOG
        print(msg)
        logging.critical(msg)
        exit(2)                                                                                                             #NAGIOS CRITICAL EXIT

#### Stage 1 Main - IP Check ####

IPcheck(PriIP, "Pri")                                                                                                       #CALL TO CHECK PRI PING
IPcheck(StbIP, "Stb")                                                                                                       #CALL TO CHECK STB PING

#### Stage 2 Main - SSH check####

SSHCheck(PriIP,PriUser,PriPass, "Pri")                                                                                      #CALL TO CHECK PRI SSH
SSHCheck(StbIP,StbUser,StbPass, "Stb")                                                                                      #CALL TO CHECK STB SSH

#### Stage 3 Main - DIR grab and Check ####

dirpri = DIRCheck(PriIP,PriUser,PriPass, "Pri", PriLoc)                                                                     #CALL TO SET PRI FOLDER LIST
dirstb = DIRCheck(StbIP,StbUser,StbPass, "Stb", StbLoc)                                                                     #CALL TO SET STB FOLDER LIST
checkDIR(dirpri, dirstb)                                                                                                    #CALL TO CHECK DIR FOR MATCH

#### Stage 4 Main - Nagios Report ####

print("Backup files are upto date")                                                                                         #MSG TO NAGIOS
exit(0)                                                                                                                     #NAGIOS OK EXIT
