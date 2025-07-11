import requests
import getpass
import warnings
from colorama import Fore, Style, init
import argparse
import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, WebDriverException
from requests.packages.urllib3.exceptions import InsecureRequestWarning, DependencyWarning as RequestsDependencyWarning
from requests_ip_rotator import ApiGateway

warnings.simplefilter("ignore", InsecureRequestWarning)
warnings.simplefilter("ignore", RequestsDependencyWarning)
init(autoreset=True)

GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

user_agents = {
    "Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3",
    "Linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/88.0.4324.96 Safari/537.36",
    "MacOS": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Android": "Mozilla/5.0 (Linux; Android 10; Pixel 3) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36",
    "iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "WindowsPhone": "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1116) AppleWebKit/537.36 Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"
}

apis = {
    "AAD Graph API": "https://graph.windows.net/",
    "Microsoft Graph API": "https://graph.microsoft.com/",
    "Service Management API": "https://management.core.windows.net/",
}

def print_logo():
    print(fr"""{CYAN}
  _   _         _____                           _
 | \ | |       |  __ \                         | |
 |  \| | ___   | |__) | __ ___  _ __ ___  _ __ | |_
 | . ` |/ _ \  |  ___/ '__/ _ \| '_ ` _ \| '_ \| __|
 | |\  | (_) | | |   | | | (_) | | | | | | |_) | |_
 |_| \_|\___/  |_|   |_|  \___/|_| |_| |_| .__/ \__|
                                        | |
                                        |_|
{YELLOW}Password-Only Access Detector for Entra ID APIs & Web Login{RESET}
""")



def parse_args():
    parser = argparse.ArgumentParser(description="Check password-only access for Entra ID APIs and login.microsoftonline.com.")
    parser.add_argument("--useragent", "-u", nargs="+", default=["all"],
                        help="Choose one or more user agents (Windows, Linux, MacOS, Android, iPhone, WindowsPhone, all)")
    parser.add_argument("--credfile", help="File with multiple credentials (format: email:password per line)")
    parser.add_argument("--iprotator", action="store_true", help="Enable IP rotation using AWS API Gateway")
    parser.add_argument("--iprotator-region", default=None, help="AWS region for IP rotation (e.g., us-east-1, eu-west-1, all)")
    parser.add_argument("--iprotator-agent", nargs="+", default=["all"],
                        help="Run IP rotation for specific agents (e.g., Windows Linux) or all")
    return parser.parse_args()


def read_credentials(file_path):
    creds = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if ":" in line:
                    email, password = line.strip().split(":", 1)
                    creds.append((email.strip(), password.strip()))
    except Exception as e:
        print(f"{RED}Failed to read credential file: {e}{RESET}")
        sys.exit(1)
    return creds

def check_browser_login(email, password, user_agent):
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument(f"user-agent={user_agent}")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except WebDriverException:
        return f"{RED}🔒 Blocked Requires MFA{RESET}"
    try:
        driver.get("https://login.microsoftonline.com/")
        time.sleep(3)
        driver.find_element(By.NAME, "loginfmt").send_keys(email)
        driver.find_element(By.ID, "idSIButton9").click()
        time.sleep(3)
        driver.find_element(By.NAME, "passwd").send_keys(password)
        driver.find_element(By.ID, "idSIButton9").click()
        time.sleep(5)
        source = driver.page_source.lower()
        if any(keyword in source for keyword in ["approve sign in request", "additional verification", "authenticator app"]):
            return f"{RED}🔒 Blocked Requires MFA{RESET}"
        elif "stay signed in" in source or "idsibutton9" in source:
            return f"{GREEN}✅ Access Granted{RESET}"
        else:
            return f"{RED}🔒 Blocked Requires MFA{RESET}"
    except Exception:
        return f"{RED}🔒 Blocked Requires MFA{RESET}"
    finally:
        driver.quit()

def check_api_access(email, password, agent_name, user_agent):
    print(f"{CYAN}==== Testing User Agent: {agent_name} ===={RESET}")
    for api_name, resource in apis.items():
        headers = {
            'User-Agent': user_agent,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'password',
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
            'resource': resource,
            'username': email,
            'password': password,
            'scope': 'openid'
        }
        try:
            resp = requests.post("https://login.microsoftonline.com/common/oauth2/token", data=data, headers=headers)
            if resp.status_code == 200 and 'access_token' in resp.json():
                result = f"{GREEN}✅ Access Granted{RESET}"
            else:
                result = f"{RED}🔒 Blocked Requires MFA{RESET}"
        except Exception:
            result = f"{RED}🔒 Blocked Requires MFA{RESET}"
        print(f"   {api_name:<30} | {result}")
    browser_result = check_browser_login(email, password, user_agent)
    print(f"   Web Login Check                 | {browser_result}\n")

# ... [imports stay the same] ...

def perform_iprotator_test(email, password, region, agent_selection="all"):
    print(f"\n{CYAN}######### IP ROTATOR RESULTS - REGION: {region} #########{RESET}\n")

    # Normalize input list
    if isinstance(agent_selection, str):
        agent_selection = [agent_selection]

    agent_selection = [ua.lower() for ua in agent_selection]

    if "all" in agent_selection:
        agents_to_test = list(user_agents.items())
    else:
        agents_to_test = [(k, v) for k, v in user_agents.items() if k.lower() in agent_selection]

    if not agents_to_test:
        print(f"{RED}Invalid user agent(s) for IP rotator: {agent_selection}{RESET}")
        return

    success_count = 0
    fail_count = 0

    try:
        if region == "random":
            gateway = ApiGateway("https://login.microsoftonline.com", verbose=True)
        else:
            gateway = ApiGateway("https://login.microsoftonline.com", regions=[region], verbose=False)
        gateway.start()

        session = requests.Session()
        session.mount("https://login.microsoftonline.com", gateway)

        for agent_name, user_agent in agents_to_test:
            print(f"{YELLOW}[ {agent_name} ]{RESET}")
            headers = {
                'User-Agent': user_agent,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            for api_name, resource in apis.items():
                data = {
                    'grant_type': 'password',
                    'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                    'resource': resource,
                    'username': email,
                    'password': password,
                    'scope': 'openid'
                }
                try:
                    resp = session.post("https://login.microsoftonline.com/common/oauth2/token", data=data, headers=headers)
                    if resp.status_code == 200 and 'access_token' in resp.json():
                        token = resp.json()['access_token']
                        print(f"   {GREEN}✓ {api_name:<25} → Access Token Granted{RESET}")
                        print(f"     {CYAN}Token:{RESET} {token}\n")
                        success_count += 1
                    else:
                        print(f"   {RED}✗ {api_name:<25} → Blocked / MFA Required{RESET}")
                        fail_count += 1
                except Exception as e:
                    print(f"   {RED}✗ {api_name:<25} → Error: {str(e)}{RESET}")
                    fail_count += 1
            print()

        print(f"{CYAN}{'-' * 45}{RESET}")
        print(f"{CYAN}Total Agents Tested: {len(agents_to_test)} | Successful: {success_count} | Blocked: {fail_count}{RESET}\n")
        gateway.shutdown()
    except Exception as e:
        print(f"{RED}Failed to run rotator: {e}{RESET}")

def main():
    args = parse_args()
    print_logo()

    credentials = []
    if args.credfile:
        credentials = read_credentials(args.credfile)
    else:
        email = input("Enter your email: ")
        password = getpass.getpass("Enter your password: ")
        credentials.append((email, password))


    # Estimate user agents to be used
    if "all" in [ua.lower() for ua in args.useragent]:
        general_agents_count = len(user_agents)
    else:
        general_agents_count = len(args.useragent)

    if args.iprotator:
        if "all" in [ua.lower() for ua in args.iprotator_agent]:
            rotator_agents_count = len(user_agents)
        else:
            rotator_agents_count = len(args.iprotator_agent)
    else:
        rotator_agents_count = 0

    # Calculate total requests
    total_requests = 0
    total_requests += len(credentials) * general_agents_count * (len(apis) + 1)  # General Check
    total_requests += len(credentials) * rotator_agents_count * len(apis)        # IP Rotator Check

    if total_requests > 150:
        print(f"{YELLOW}⚠️  Estimated total requests: {total_requests}.{RESET}")
        print(f"{YELLOW}This may trigger detection or alerts on Microsoft/Entra systems.{RESET}")
        choice = input(f"{CYAN}Do you want to continue? (yes/no): {RESET}").strip().lower()
        if choice not in ["yes", "y"]:
            print(f"{RED}Aborting script to avoid triggering alerts.{RESET}")
            sys.exit(0)


    # General Access Check
    selected_agents = [ua.lower() for ua in args.useragent]
    if "all" in selected_agents:
        agents = user_agents.items()
    else:
        agents = [(k, v) for k, v in user_agents.items() if k.lower() in selected_agents]

    if not agents:
        print(f"{RED}Invalid user agent(s): {args.useragent}{RESET}")
        print("Valid options are: " + ", ".join(user_agents.keys()) + ", all")
        sys.exit(1)


    for idx, (email, password) in enumerate(credentials, 1):
        print(f"\n{CYAN}######### PASSWORD-ONLY ACCESS CHECK #{idx} #########{RESET}")
        print(f"{YELLOW}Email: {GREEN}{email}{RESET} | Password: {GREEN}{password}{RESET}\n")
        for name, ua in agents:
            check_api_access(email, password, name, ua)

    # IP Rotator Test
    if args.iprotator:
        if not args.iprotator_region:
            print(f"{RED}--iprotator is set but no region provided. Use --iprotator-region or type 'all'.{RESET}")
            sys.exit(1)
        for email, password in credentials:
            perform_iprotator_test(email, password, args.iprotator_region, args.iprotator_agent)

if __name__ == '__main__':
    main()
