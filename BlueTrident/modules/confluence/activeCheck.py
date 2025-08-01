import requests
import json
import shutil
import sys

from colorama import Fore, Back, Style

from ..support.args import parser

class ActiveConfluence:
    
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
        size = ActiveConfluence.size()
        print(Fore.GREEN + Style.BRIGHT + '-' * size + '\n' + 'ACTIVE-SCAN-RESULT'.center(size) + '\n' + '-' * size + Style.RESET_ALL + '\n')
        print(Fore.CYAN + "CVE-ID" + "\t\t\t" + "SEVERITY" + "\t" + "POC-URL" + Style.RESET_ALL + '\n')
    