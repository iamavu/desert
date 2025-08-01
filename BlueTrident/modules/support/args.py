import argparse

def parser():
    parser = argparse.ArgumentParser(description=None)
    positional = parser.add_argument_group('positional arguments')
    optional = parser.add_argument_group('optional arguments')
    module = parser.add_mutually_exclusive_group(required=True)
    mode = parser.add_argument_group('mode arguments')
    module.add_argument('--jira', help='use jira module', action='store_true', required=False)
    module.add_argument('--confluence', help='use confluence module', action='store_true', required=False)
    module.add_argument('--bitbucket', help='use bitbucket module', action='store_true', required=False)
    mode.add_argument('--active', help='actively check and confirm for CVEs', action='store_true', required=False)
    mode.add_argument('--passive', help='passively predict CVEs for the target', action='store_true', required=False)
    optional.add_argument('--user', help='user for validating some CVEs', default='admin', required=False)
    positional.add_argument('target', help='domain name to perform scan on')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parser()