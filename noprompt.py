import requests
import getpass
import warnings
from colorama import Fore, Style, init
import argparse
import sys
import time
import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, WebDriverException
from requests.packages.urllib3.exceptions import InsecureRequestWarning, DependencyWarning as RequestsDependencyWarning
from requests_ip_rotator import ApiGateway

warnings.simplefilter("ignore", InsecureRequestWarning)
warnings.simplefilter("ignore", RequestsDependencyWarning)
init(autoreset=True)

# Color constants
GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# AWS regions with full country information
AWS_REGIONS = {
    "us-east-1": {"name": "US East (N. Virginia)", "country": "United States"},
    "us-east-2": {"name": "US East (Ohio)", "country": "United States"},
    "us-west-1": {"name": "US West (N. California)", "country": "United States"},
    "us-west-2": {"name": "US West (Oregon)", "country": "United States"},
    "ap-south-1": {"name": "Asia Pacific (Mumbai)", "country": "India"},
    "ap-northeast-1": {"name": "Asia Pacific (Tokyo)", "country": "Japan"},
    "ap-northeast-2": {"name": "Asia Pacific (Seoul)", "country": "South Korea"},
    "ap-northeast-3": {"name": "Asia Pacific (Osaka)", "country": "Japan"},
    "ap-southeast-1": {"name": "Asia Pacific (Singapore)", "country": "Singapore"},
    "ap-southeast-2": {"name": "Asia Pacific (Sydney)", "country": "Australia"},
    "ca-central-1": {"name": "Canada (Central)", "country": "Canada"},
    "eu-central-1": {"name": "Europe (Frankfurt)", "country": "Germany"},
    "eu-west-1": {"name": "Europe (Ireland)", "country": "Ireland"},
    "eu-west-2": {"name": "Europe (London)", "country": "United Kingdom"},
    "eu-west-3": {"name": "Europe (Paris)", "country": "France"},
    "eu-north-1": {"name": "Europe (Stockholm)", "country": "Sweden"},
    "sa-east-1": {"name": "South America (São Paulo)", "country": "Brazil"},
}

# User agents for different platforms
user_agents = {
    "Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.3",
    "Linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/88.0.4324.96 Safari/537.36",
    "MacOS": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Android": "Mozilla/5.0 (Linux; Android 10; Pixel 3) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36",
    "iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "WindowsPhone": "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1116) AppleWebKit/537.36 Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"
}

# Microsoft APIs to test
apis = {
    "AAD Graph API": "https://graph.windows.net/",
    "Microsoft Graph API": "https://graph.microsoft.com/",
    "Service Management API": "https://management.core.windows.net/",
}

# Track all created gateways for cleanup
created_gateways = []

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
    parser.add_argument("--iprotator-region", default=None,
                        help="AWS region for IP rotation (e.g., us-east-1, 'all' for all regions, 'random' for random regions)")
    parser.add_argument("--iprotator-agent", nargs="+", default=["all"],
                        help="Run IP rotation for specific agents (e.g., Windows Linux) or all")
    parser.add_argument("--attempts", type=int, default=10,
                        help="Number of attempts to try with different IPs in random mode")
    parser.add_argument("--show-token", action="store_true",
                        help="Show full access token in output (warning: sensitive information)")
    return parser.parse_args()

def cleanup_gateways():
    """Clean up all created API gateways"""
    print(f"\n{YELLOW}Cleaning up API gateways...{RESET}")
    success = 0
    failures = 0

    for gateway_info in created_gateways:
        try:
            gateway = gateway_info['gateway']
            if hasattr(gateway, 'shutdown'):
                gateway.shutdown()
                success += 1
        except Exception as e:
            failures += 1

    created_gateways.clear()
    print(f"{CYAN}Cleanup complete. Success: {success}, Failures: {failures}{RESET}")

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

def perform_iprotator_test(email, password, region, agent_selection="all", attempts=10, show_token=False):
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

    if region == "all":
        for aws_region in AWS_REGIONS:
            print(f"\n{CYAN}######### IP ROTATOR RESULTS - REGION: {AWS_REGIONS[aws_region]['name']} ({AWS_REGIONS[aws_region]['country']}) #########{RESET}\n")
            _run_iprotator_test(email, password, aws_region, agents_to_test, show_token)
    elif region == "random":
        print(f"\n{CYAN}######### IP ROTATOR RESULTS - RANDOM REGIONS (Attempts: {attempts}) #########{RESET}\n")
        _run_iprotator_test_random(email, password, agents_to_test, attempts, show_token)
    else:
        if region not in AWS_REGIONS:
            print(f"{RED}Invalid AWS region: {region}{RESET}")
            print("Available regions:")
            for code, info in AWS_REGIONS.items():
                print(f"  {code}: {info['name']} ({info['country']})")
            return
        print(f"\n{CYAN}######### IP ROTATOR RESULTS - REGION: {AWS_REGIONS[region]['name']} ({AWS_REGIONS[region]['country']}) #########{RESET}\n")
        _run_iprotator_test(email, password, region, agents_to_test, show_token)

def _run_iprotator_test(email, password, region, agents_to_test, show_token=False):
    success_count = 0
    fail_count = 0

    try:
        gateway = ApiGateway("https://login.microsoftonline.com", regions=[region], verbose=False)
        gateway.start()
        created_gateways.append({
            'gateway': gateway,
            'region': region
        })

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
                        if show_token:
                            print(f"     {CYAN}Full Token:{RESET} {token}\n")
                        else:
                            print(f"     {CYAN}Token:{RESET} {token[:50]}...{token[-10:]}\n")
                        success_count += 1
                    else:
                        print(f"   {RED}✗ {api_name:<25} → Blocked / MFA Required{RESET}")
                        fail_count += 1
                except Exception as e:
                    print(f"   {RED}✗ {api_name:<25} → Error: {str(e)}{RESET}")
                    fail_count += 1
            print()

        print(f"{CYAN}{'-' * 45}{RESET}")
        print(f"{CYAN}Region: {AWS_REGIONS[region]['name']} ({AWS_REGIONS[region]['country']}) | Agents Tested: {len(agents_to_test)} | Successful: {success_count} | Blocked: {fail_count}{RESET}\n")
    except Exception as e:
        print(f"{RED}Failed to run rotator in region {region}: {e}{RESET}")

def _run_iprotator_test_random(email, password, agents_to_test, attempts=10, show_token=False):
    success_count = 0
    fail_count = 0

    try:
        # Select random regions (up to the number of attempts)
        selected_regions = random.sample(list(AWS_REGIONS.keys()), min(attempts, len(AWS_REGIONS)))
        print(f"{YELLOW}Selected {len(selected_regions)} random regions:{RESET}")
        for region in selected_regions:
            print(f"  {region}: {AWS_REGIONS[region]['name']} ({AWS_REGIONS[region]['country']})")
        print()

        for agent_name, user_agent in agents_to_test:
            print(f"{YELLOW}[ {agent_name} ]{RESET}")
            headers = {
                'User-Agent': user_agent,
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            for api_name, resource in apis.items():
                # Try with each random region
                for i, region in enumerate(selected_regions, 1):
                    try:
                        gateway = ApiGateway("https://login.microsoftonline.com", regions=[region], verbose=False)
                        gateway.start()
                        created_gateways.append({
                            'gateway': gateway,
                            'region': region
                        })
                        session = requests.Session()
                        session.mount("https://login.microsoftonline.com", gateway)

                        data = {
                            'grant_type': 'password',
                            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                            'resource': resource,
                            'username': email,
                            'password': password,
                            'scope': 'openid'
                        }

                        resp = session.post("https://login.microsoftonline.com/common/oauth2/token",
                                          data=data,
                                          headers=headers)

                        if resp.status_code == 200 and 'access_token' in resp.json():
                            token = resp.json()['access_token']
                            print(f"   {GREEN}✓ {api_name:<25} → Access Token Granted (Region {i}/{len(selected_regions)}: {AWS_REGIONS[region]['name']} ({AWS_REGIONS[region]['country']})){RESET}")
                            if show_token:
                                print(f"     {CYAN}Full Token:{RESET} {token}\n")
                            else:
                                print(f"     {CYAN}Token:{RESET} {token[:50]}...{token[-10:]}\n")
                            success_count += 1
                            break  # Success, move to next API
                        else:
                            print(f"   {YELLOW}✗ {api_name:<25} → Attempt {i}/{len(selected_regions)} ({AWS_REGIONS[region]['name']}) - Blocked{RESET}")
                            if i == len(selected_regions):  # Last attempt
                                print(f"   {RED}✗ {api_name:<25} → All attempts failed{RESET}")
                                fail_count += 1
                    except Exception as e:
                        print(f"   {RED}✗ {api_name:<25} → Attempt {i}/{len(selected_regions)} ({AWS_REGIONS[region]['name']}) - Error: {str(e)}{RESET}")
                        if i == len(selected_regions):  # Last attempt
                            fail_count += 1
                    finally:
                        try:
                            session.close()
                        except:
                            pass
            print()

        print(f"{CYAN}{'-' * 45}{RESET}")
        print(f"{CYAN}Random Regions Tested: {len(selected_regions)} | Agents Tested: {len(agents_to_test)} | Successful: {success_count} | Blocked: {fail_count}{RESET}\n")
    except Exception as e:
        print(f"{RED}Failed to run random region rotator: {e}{RESET}")

def main():
    args = parse_args()
    print_logo()

    try:
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

        if args.iprotator:
            if args.iprotator_region == "all":
                total_requests += len(credentials) * rotator_agents_count * len(AWS_REGIONS) * len(apis)
            elif args.iprotator_region == "random":
                total_requests += len(credentials) * rotator_agents_count * len(apis) * args.attempts
            else:  # Single region
                total_requests += len(credentials) * rotator_agents_count * len(apis)

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
            print(f"{YELLOW}Email: {GREEN}{email}{RESET}\n")
            for name, ua in agents:
                check_api_access(email, password, name, ua)

        # IP Rotator Test
        if args.iprotator:
            if not args.iprotator_region:
                print(f"{RED}--iprotator is set but no region provided. Use --iprotator-region or type 'all' or 'random'.{RESET}")
                sys.exit(1)
            for email, password in credentials:
                perform_iprotator_test(email, password, args.iprotator_region, args.iprotator_agent, args.attempts, args.show_token)

    finally:
        # Clean up all created gateways
        cleanup_gateways()

if __name__ == '__main__':
    main()
