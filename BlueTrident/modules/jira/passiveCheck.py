import requests
import json
import shutil

from colorama import Fore, Back, Style

from ..support.args import parser

class PassiveJira:
    def __init__(self):
        args = parser()
        self.target = args.target
    
    def tidy_url(target):
        if target.endswith('/'):
            target = target[:-1]
        return target
    
    def size():
        return shutil.get_terminal_size().columns
    
    def getSeverInfo(self, target):
        size = PassiveJira.size()
        target = PassiveJira.tidy_url(target)     
        
        if target.startswith('https://') == False and target.startswith('http://') == False:
            print(Fore.RED + '[-] Error: Protocol not specified (http or https)' + Style.RESET_ALL)
            exit()
        
        response = requests.get(target + '/rest/api/latest/serverInfo')
        server_data = json.loads(str(response.content, 'utf-8'))
        print(Fore.GREEN + Style.BRIGHT + '-' * size + '\n' + 'SERVER-INFO'.center(size) + '\n' + '-' * size + Style.RESET_ALL)
        print(Fore.LIGHTBLUE_EX + f"URL" + Style.RESET_ALL + "\t\t\t\t\t" + f"{server_data.get('baseUrl')}")
        print(Fore.LIGHTBLUE_EX + f"Server Title" + Style.RESET_ALL + "\t\t\t\t" + f"{server_data.get('serverTitle')}")
        print(Fore.LIGHTBLUE_EX + f"Version" + Style.RESET_ALL + "\t\t\t\t\t" + f"{server_data.get('version')}")
        print(Fore.LIGHTBLUE_EX + f"Build Number" + Style.RESET_ALL + "\t\t\t\t" + f"{server_data.get('buildNumber')}")
        global version 
        version = server_data.get('version')
    
    def cveCheck(self):
        size = PassiveJira.size()
        session = requests.Session()
        response = session.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + f"cpe:2.3:a:atlassian:jira_server:{version}:*:*:*:*:*:*:*")
        cveData = json.loads(response.content)
        print(Fore.GREEN + Style.BRIGHT + '-' * size + '\n' + 'PASSIVE-SCAN-RESULT'.center(size) + '\n' + '-' * size + Style.RESET_ALL)
        
        
        ids = []
        severity = []
        for i in range(cveData.get('totalResults')):
            ids.append(cveData.get('vulnerabilities')[i].get('cve').get('id'))
            severity.append(cveData.get('vulnerabilities')[i].get('cve').get('metrics').get('cvssMetricV31')[0].get('cvssData').get('baseSeverity'))
        results = dict(zip(ids, severity))
        results = dict(reversed(list(results.items())))
        print(Fore.LIGHTBLUE_EX + "List of possible CVEs and misconfigurations\n" + Style.RESET_ALL)
        for key, value in results.items():
            if value == 'CRITICAL':
                print(f"{key}\t\t\t\t" + Fore.RED + f"{value}" + Style.RESET_ALL)
            elif value == 'HIGH':
                print(f"{key}\t\t\t\t" + Fore.LIGHTRED_EX + f"{value}" + Style.RESET_ALL)
            elif value == 'MEDIUM':
                print(f"{key}\t\t\t\t" + Fore.YELLOW + f"{value}" + Style.RESET_ALL)
            elif value == 'LOW':
                print(f"{key}\t\t\t\t" + Fore.GREEN + f"{value}" + Style.RESET_ALL)
            else:
                print(f"{key}\t\t\t\t" + Fore.CYAN + f"{value}" + Style.RESET_ALL)
        print('\n')
        
class MisconfigJira():
    
    def __init__(self):
        args = parser()
        self.target = args.target
    
    def signup(self, target):
        poc1 = target + '/servicedesk/customer/user/signup'
        poc2 = target + '/secure/Signup!default.jspa'
        poc3 = target + '/servicedesk/customer/user/signup'
        poc4 = target + '/secure/Signup.jspa'
        
        data3 = '"email":"","fullname":"leet","password":"","captcha":"","secondaryEmail":""}'
        data4 = 'email=&fullname=leet&username=&password=&Signup=Sign+up'
                
        response1 = requests.get(poc1)
        response2 = requests.get(poc2)
        response3 = requests.post(poc3, data=data3)
        response4 = requests.post(poc4, data=data4)
        
        if b'signup.validation.errors' in response1.content or b'signup-username-error' in response1.content:
            print(Fore.YELLOW + "User sign-up enabled" + Style.RESET_ALL + "\t\t\t" + f"{poc1}")
        elif b'signup.validation.errors' in response2.content or b'signup-username-error' in response2.content:
            print(Fore.YELLOW + "User sign-up enabled" + Style.RESET_ALL + "\t\t\t" + f"{poc2}")
        elif b'signup.validation.errors' in response3.content or b'signup-username-error' in response3.content:
            print(Fore.YELLOW + "User sign-up enabled" + Style.RESET_ALL + "\t\t\t" + f"{poc3}")
        elif b'signup.validation.errors' in response4.content or b'signup-username-error' in response4.content:
            print(Fore.YELLOW + "User sign-up enabled" + Style.RESET_ALL + "\t\t\t" + f"{poc4}")
    
    def unauth_admin_projects(self, target):
        poc = target + '/rest/menu/latest/admin'
        response = requests.get(poc)
        
        if b'"key":"admin"' in response.content and response.status_code == 200:
           print(Fore.CYAN + "Unauthenticated admin projects" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def unauth_dashboard(self, target):
        poc = target + '/rest/api/latest/dashboard?maxResults=100'
        response = requests.get(poc)
        
        if b'"startAt":0,"maxResults":100' in response.content and response.status_code == 200:
            print(Fore.CYAN + "Unauthenticated dashboards" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def unauth_gadgets(self, target):
        poc = target + '/rest/config/1.0/directory'
        response = requests.get(poc)
        
        if b'jaxbDirectoryContents' in response.content and response.status_code == 200:
            print(Fore.CYAN + "Unauthenticated installed gadgets" + Style.RESET_ALL + "\t" + f"{poc}")
            
    def unauth_projects_categories(self, target):
        poc = target + '/rest/api/latest/projectCategory?maxResults=1000'
        response = requests.get(poc)
        
        if b'description' in response.content and response.status_code == 200:
            print(Fore.CYAN + "Unauthenticated project categories" + Style.RESET_ALL + "\t" + f"{poc}")
    
    def unauth_projects(self, target):
        poc = target + '/rest/api/latest/project?maxResults=100'
        response = requests.get(poc)
        
        if b'description,lead,url,projectKeys' in response.content:
            print(Fore.CYAN + "Unauthenticated projects" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def unauth_resolutions(self, target):
        poc = target + '/rest/api/latest/resolution'
        response = requests.get(poc)        

        if b'description' in response.content:
            print(Fore.CYAN + "Unauthenticated projects" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def unauth_screens(self, target):
        poc = target + '/rest/api/latest/screens'
        response = requests.get(poc)
        
        if b'description' in response.content:
            print(Fore.CYAN + "Unauthenticated screens" + Style.RESET_ALL + "\t\t\t" + f"{poc}")
    
    def unauth_user_picker(self, target):
        poc = target + '/secure/popups/UserPickerBrowser.jspa'
        response = requests.get(poc)
        
        if b'user-picker' in response.content:
            print(Fore.CYAN + "Unauthenticated user picker" + Style.RESET_ALL + "\t\t" + f"{poc}")

if __name__ == '__main__':
    PassiveJira()
    MisconfigJira()