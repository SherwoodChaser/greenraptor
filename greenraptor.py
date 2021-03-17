#!/usr/bin/python3
import requests
from bs4 import BeautifulSoup
from termcolor import colored
from argparse import ArgumentParser
import datetime
from urllib.parse import urljoin

print(colored("""
\t____ ____ ____ ____ _  _ ____ ____ ___  ___ ____ ____ 
\t| __ |__/ |___ |___ |\ | |__/ |__| |__]  |  |  | |__/ 
\t|__] |  \ |___ |___ | \| |  \ |  | |     |  |__| |  \ 
\t\t Developed By {}
""", "green", attrs=['bold']).format(colored("Sherwood Chaser", "white")))

argopt = ArgumentParser()
argopt.add_argument("--url", "-u", help="Specify URL To Scan.")
argopt.add_argument("--payload", "-p", help="Specify Payload.")
argopt.add_argument("--match", "-ms", help="Match String In Response.")
options = argopt.parse_args()

open_bracket = colored("[",attrs=['bold'])
close_bracket = colored("]",attrs=['bold'])

def scanner(url, payload, err_msg):
    try:
        print(colored("[+] Target URL : ", attrs=['bold']), colored(f"{url}", "blue", attrs=['bold', 'underline']), end="")

        response = requests.get(url)
        soup = BeautifulSoup(response.text, "lxml")

        print(" " + open_bracket + colored(f"{response.status_code}", "green", attrs=['bold']) + close_bracket, end="")

        try:
            print(" " + open_bracket + colored(f" {soup.title.text} ", "green", attrs=['bold']) + close_bracket, end='')
        except AttributeError:
            print(" " + open_bracket + colored(" No Title ", "red", attrs=['bold']) + close_bracket, end='')
        
        try:
            print(" " + open_bracket + colored(f" {response.headers['server']} ", "green", attrs=['bold']) + close_bracket)
        except KeyError:
            print(" " + open_bracket + colored(" Server Not Detected ", "red", attrs=['bold']) + close_bracket)

        find_form = soup.find("form")

        if find_form:
            method_used = find_form.get("method")
            action_url = urljoin(url, find_form.get("action"))
            form_data = {}

            print(open_bracket + colored("INFO", 'cyan', attrs=['bold']) + close_bracket + 
            colored(" Form Found !", attrs=['bold']))
            print(open_bracket + colored(f"INFO", "cyan", attrs=['bold']) + close_bracket + 
            colored(f" Method used ", attrs=['bold']) + colored(f"\"{method_used}\"","magenta" , attrs=['bold']))
            
            for param in find_form.find_all("input"):
                if param.get("type") != "submit":
                    print(open_bracket + colored("INFO", 'cyan', attrs=['bold']) + close_bracket + 
                    colored(f" Found Parameter ", attrs=['bold']) + 
                    colored(f"\"{param.get('name')}\"", "magenta", attrs=['bold']))

                    print(open_bracket + colored("TESTING", 'green', attrs=['bold']) + close_bracket + 
                    colored(" Checking For Vuln", attrs=['bold']))
                    form_data[param.get("name")] = payload
                else:
                    form_data[param.get("name")] = param.get('value')

            if method_used == "post":
                re = requests.post(action_url, data=form_data)
            else:
                re = requests.get(action_url, params=form_data)
            
            if err_msg in re.text:
                print(open_bracket + colored("WARNING", "red", attrs=['bold']) + close_bracket + 
                colored(f" Vuln FOUND, POC : {re.url}", attrs=['bold']), "\n")
            else:
                print(open_bracket + colored("SECURE", "green", attrs=['bold']) + close_bracket + 
                colored(f" NO Vuln FOUND : {action_url}", attrs=['bold']), "\n")
        else:
            print(open_bracket + "!" + close_bracket + colored(" Form Not Found ", "red", attrs=['bold']))

    except:
        print(colored(" [ Not Found ]", "red", attrs=['bold']))
    
    

if options.url and options.payload and options.match:
    scanner(options.url, options.payload, options.match)
