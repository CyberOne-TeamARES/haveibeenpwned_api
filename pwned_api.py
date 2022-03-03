#!/usr/bin/env python

###############################################################################################################
# Author: Paragonsec (Quentin) @ CyberOne
# Title: pwned_api.py
# Version: 2.0
# Usage Example: python pwned_api.py -h
# Description: This script queries the 'haveibeenpwned' API
# Data obtained from: https://haveibeenpwned.com/
# 
# Requirements: cfscrape (pip install cfscrape)
###############################################################################################################

import requests
import time
import sys
import cfscrape
import argparse
import json
import os

# Arguments
parser = argparse.ArgumentParser(description="Used to verify if email addresses have been breached.")

parser.add_argument("-a", dest="address",
                  help="Single email address to be checked")
parser.add_argument("-af", dest="filename",
                  help="File to be checked with one email addresses per line")
parser.add_argument("-ab", "--allbreaches",
                  help="Obtain all breaches in system", action="store_true")
parser.add_argument("-n", dest="name",
                  help="Company name to check")
parser.add_argument("-b", "--breachsearch",
                  help="Set if looking for breaches with a file", action="store_true")
parser.add_argument("-bf", dest="breachfile",
                  help="File containing names to search for breaches")
parser.add_argument("-p", "--pastes",
                  help="Obtain pastes from file after initial search is done", action="store_true")

args = parser.parse_args()


# Colors to make things look more l33t
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
OKRED = '\033[91m'
WARNING = '\033[93m'
FAIL = '\033[1;91m'
ENDC = '\033[0m'


rate = 2.0 # Time to prevent rate limiting issue
endpoint = "haveibeenpwned.com" # API Website
cfdirectory = "/api/breachedaccount/test@example.com" # API Request to bypass cloudflare
sslVerify = True


# User set arguments
address = str(args.address)
filename = str(args.filename)
bfilename = str(args.breachfile)
name = str(args.name)


# Obtaining necessary cookie
cookies, user_agent = cfscrape.get_tokens("https://" + endpoint + cfdirectory, user_agent="PwnChecker-API-Python-Script")


# Need to fix and use cfscrape instead of a new variable
useragent = {'User-Agent' : 'PwnChecker-API-Python-Script'}

# Main Directory for file output
directory = "Output"
if not os.path.exists(directory):
	os.makedirs(directory)
	print OKBLUE + "[+] Making directory for all output!" + ENDC

def main():
    # Setting global variables as "name" was throwing errors.
    global address
    global filename
    global bfilename
    global name
    global pastes

    print OKBLUE + "[!] Cookie Value being used is: " + ENDC + str(cookies)
    print OKBLUE + "[!] User Agent being used is: " + ENDC + str(useragent) + "\n"
    
    if address != "None":
        print OKBLUE + "[+] Checking single address now!" + ENDC + "\n"
        checkEmail(address)
        if args.pastes:
            print "\n" + OKBLUE + "[+] Obtaining pastes from accounts that were breached!" + ENDC + "\n"
            account = [line.rstrip('\n') for line in open("Output/breached_accounts.txt")] # Open the created breached_accounts.txt file that was created in checkEmail
            for account in account:
                obtainPastes(account)
    elif filename != "None":
        print OKBLUE + "[+] Checking list of addresses now!" + ENDC + "\n"
        email = [line.rstrip('\n') for line in open(filename)] # Strip the newlines out of the file
        for email in email:
            checkEmail(email)
        if args.pastes:
            print "\n" + OKBLUE + "[+] Obtaining pastes from accounts that were breached!" + ENDC + "\n"
            account = [line.rstrip('\n') for line in open("Output/breached_accounts.txt")] # Open the created breached_accounts.txt file that was created in checkEmail
            for account in account:
                obtainPastes(account)

    elif args.allbreaches:
        print OKBLUE + "[+] Getting all breaches in system!" + ENDC + "\n" 
        allBreaches()
    elif name != "None":
        print OKBLUE + "[+] Checking single breach now!" + ENDC + "\n"
        checkBreach(name)
    elif bfilename != "None":
        print OKBLUE + "[+] Checking list of breaches now!" + ENDC + "\n"
        name = [line.rstrip('\n') for line in open(bfilename)] # Strip the newlines out of the file
        for name in name:
            checkBreach(name)
    else:
        print FAIL + "[!] Nothing to do! Exiting" + ENDC
        sys.exit()


# Obtain all breaches by email address
def checkEmail(email):
    f = open("Output/breached_accounts.txt", "a+")
    sleep = rate
    req = requests.get("https://" + endpoint + "/api/breachedaccount/" + email, headers = useragent, cookies = cookies, verify = sslVerify)
    # The address has not been breached
    if str(req.status_code) == "404":
        print OKGREEN + "[!] " + email + " has not been breached." + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return False
    # The address as been breached
    elif str(req.status_code) == "200":
        print OKRED + "[!] " + email + " has been breached!" + ENDC
        f.write(email + "\n")
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True
    # Rate limit triggered
    elif str(req.status_code) == "429":
        print WARNING + "[!] Rate limit exceeded, server instructed us to retry after " + req.headers['Retry-After'] + " seconds" + ENDC
        # Checking to see if the server has limited us for a long time or possibly banned us
        if str(req.headers['Retry-After']) <= 300:
            print FAIL + "[!] Server has rate limited us for longer then 5 minutes!" + ENDC
            print FAIL + "[!] Do one of the following: Be patient you crazy person, change your IP, change the URL (remove or add v2 after /api/), or just rerun the script and pray!" + ENDC
            f.close()
            sys.exit()
        else:
            sleep = float(req.headers['Retry-After']) # Read rate limit from HTTP response headers and set local sleep rate
            time.sleep(sleep) # Sleeping a little longer as the server instructed us to do
            checkEmail(email) # Reissue request
    # CloudFlare has stopped us
    elif str(req.status_code) == 503:
        print FAIL + "[!] CloudFlare has stopped our request! Ensure you are using a valid cookie with the user-agent that obtained that cookie!" + ENDC
        f.close()
        sys.exit()
    else:
        print WARNING + "[!] Something went wrong while checking " + email + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True

# Obtain pastes from breached accounts
def obtainPastes(account):
    # Directory to store all pastes in
    directory = "Output/pastes/"
    if not os.path.exists(directory):
        os.makedirs(directory)
        print OKBLUE + "[+] Making directory for pastes to be placed in!" + ENDC
    
    sleep = rate
    req = requests.get("https://" + endpoint + "/api/v2/pasteaccount/" + account, headers = useragent, cookies = cookies, verify = sslVerify)
    # The account has no pastes
    if str(req.status_code) == "404":
        print OKGREEN + "[!] " + account + " has no pastes." + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return False
    # The account has pastes
    elif str(req.status_code) == "200":
        # Files to be written to
        with open(directory + account + ".txt", "w+") as outfile:
            json.dump(req.content, outfile)

        print OKRED + "[!] " + account + " has pastes!" + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True
    # Rate limit triggered
    elif str(req.status_code) == "429":
        print WARNING + "[!] Rate limit exceeded, server instructed us to retry after " + req.headers['Retry-After'] + " seconds" + ENDC
        # Checking to see if the server has limited us for a long time or possibly banned us
        if str(req.headers['Retry-After']) <= 300:
            print FAIL + "[!] Server has rate limited us for longer then 5 minutes!" + ENDC
            print FAIL + "[!] Do one of the following: Be patient you crazy person, change your IP, change the URL (remove or add v2 after /api/), or just rerun the script and pray!" + ENDC
            f.close()
            sys.exit()
        else:
            sleep = float(req.headers['Retry-After']) # Read rate limit from HTTP response headers and set local sleep rate
            time.sleep(sleep) # Sleeping a little longer as the server instructed us to do
            obtainPastes(account) # Reissue request
    # CloudFlare has stopped us
    elif str(req.status_code) == 503:
        print FAIL + "[!] CloudFlare has stopped our request! Ensure you are using a valid cookie with the user-agent that obtained that cookie!" + ENDC
        f.close()
        sys.exit()
    else:
        print WARNING + "[!] Something went wrong while checking " + account + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True



# Obtaining all breaches
def allBreaches():
    req = requests.get("https://" + endpoint + "/api/v2/breaches", headers = useragent, cookies = cookies, verify = sslVerify)
    if str(req.status_code) == "200":
        print OKGREEN + "[!] Obtained breaches and saving to file!" + ENDC
        with open('Output/breaches.txt', 'w+') as outfile:
	    json.dump(req.content, outfile)
    else:
	print WARNING + "[!] Something went wrong while obtaining breaches" + ENDC
	sys.exit()



# Obtaining breaches by name
def checkBreach(name):
    f = open("Output/breach_query.txt", "a+")
    sleep = rate
    req = requests.get("https://" + endpoint + "/api/v2/breach/" + name, headers = useragent, cookies = cookies, verify = sslVerify)
    # The breach does not exist
    if str(req.status_code) == "404":
        print OKGREEN + "[!] " + name + " is not a valid breach." + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return False
    # The breach exists
    elif str(req.status_code) == "200":
        print OKRED + "[!] " + name + " is a breach!" + ENDC
        f.write(name + "\n")
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True
    # Rate limit triggered
    elif str(req.status_code) == "429":
        print WARNING + "[!] Rate limit exceeded, server instructed us to retry after " + req.headers['Retry-After'] + " seconds" + ENDC
        # Checking to see if the server has limited us for a long time or possibly banned us
        if str(req.headers['Retry-After']) <= 300:
            print FAIL + "[!] Server has rate limited us for longer then 5 minutes!" + ENDC
            print FAIL + "[!] Do one of the following: Be patient you crazy person, change your IP, change the URL (remove or add v2 after /api/), or just rerun the script and pray!" + ENDC
            f.close()
            sys.exit()
        else:
            sleep = float(req.headers['Retry-After']) # Read rate limit from HTTP response headers and set local sleep rate
            time.sleep(sleep) # Sleeping a little longer as the server instructed us to do
            checkBreach(name) # Reissue request
    # CloudFlare has stopped us
    elif str(req.status_code) == 503:
        print FAIL + "[!] CloudFlare has stopped our request! Ensure you are using a valid cookie with the user-agent that obtained that cookie!" + ENDC
        f.close()
        sys.exit()
    else:
        print WARNING + "[!] Something went wrong while checking " + name + ENDC
        time.sleep(sleep) # sleep so that we don't trigger the rate limit
        return True


if __name__ == "__main__":
    main()
