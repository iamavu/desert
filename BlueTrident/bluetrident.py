#bluetrident
version = '0.0.1'

from colorama import Fore, Back, Style
from functools import partial

from modules.support.args import parser
from modules.support.tidy import tidy_url
from modules.jira.passiveCheck import PassiveJira
from modules.jira.passiveCheck import MisconfigJira
from modules.jira.activeCheck import ActiveJira

def banner():
    print(Fore.MAGENTA + Style.BRIGHT + f'''

__________.__              ___________      .__    .___             __   
\______   \  |  __ __   ___\__    ___/______|__| __| _/____   _____/  |_ 
 |    |  _/  | |  |  \_/ __ \|    |  \_  __ \  |/ __ |/ __ \ /    \   __/
 |    |   \  |_|  |  /\  ___/|    |   |  | \/  / /_/ \  ___/|   |  \  |  
 |______  /____/____/  \___  >____|   |__|  |__\____ |\___  >___|  /__|  
        \/                 \/                       \/    \/     \/      
                                                                    ''' + Style.RESET_ALL + Fore.MAGENTA + f'''
                                                                    > BlueTrident v{version}
                                                                    > Created by @iamavu''' 
                                                                    )
    
    print(Style.RESET_ALL)
    
def bluetrident():
    banner()
    args = parser()
    
    target = tidy_url(args.target)
    user = args.user
    
    passivejira = PassiveJira()
    activejira = ActiveJira()
    misconfigjira = MisconfigJira()
    
    passivejira.getSeverInfo(target)
    
    
    if args.jira == True and args.passive == True:
        
        passivejira.cveCheck()

        misconfigjira.signup(target)
        misconfigjira.unauth_admin_projects(target)
        misconfigjira.unauth_dashboard(target)
        misconfigjira.unauth_gadgets(target)
        misconfigjira.unauth_projects_categories(target)
        misconfigjira.unauth_projects(target)
        misconfigjira.unauth_resolutions(target)
        misconfigjira.unauth_screens(target)
        misconfigjira.unauth_user_picker(target)
    
    if args.jira == True and args.active == True:
        
        activejira.headline()
        
        activejira.cve_2017_9506(target)
        activejira.cve_2019_3403(target, user)
        activejira.cve_2019_8446(target, user)
        activejira.cve_2020_14179(target)
        activejira.cve_2019_8449(target, user)
        activejira.cve_2020_14181(target, user)
        activejira.cve_2021_26085(target)
        activejira.cve_2018_20824(target)
        activejira.cve_2019_3402(target)
        activejira.cve_2015_8399(target)
        activejira.cve_2021_26086(target)
        activejira.cve_2020_36289(target, user)
        activejira.cve_2019_8442(target)
        activejira.cve_2019_3401(target)
        activejira.cve_2019_11581(target)
        activejira.cve_2019_3396(target)
        activejira.cve_2019_8451(target)
        activejira.cve_2020_29453(target)
        activejira.cve_2022_0540(target)
        activejira.cve_2022_39960(target)
           
            
if __name__ == '__main__':
    try:
        bluetrident()
    except KeyboardInterrupt:
        print(Fore.RED + "\nKEYBOARD INTERRUPTION RECEIVED" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nERROR : {e}" + Style.RESET_ALL)