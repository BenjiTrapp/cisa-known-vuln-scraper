import os
import requests
import argparse
import json
import re
import threading
import time
from threading import Semaphore
from dotenv import load_dotenv
from termcolor import colored

load_dotenv()

EPSS_URL = "https://api.first.org/data/v1/epss"
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NIST_API_KEY_REQUEST = "https://nvd.nist.gov/developers/request-an-api-key"
SIMPLE_HEADER = f"{'CVE-ID':<18}Priority" + "\n" + ("-" * 30)
VERBOSE_HEADER = f"{'CVE-ID':<18}{'PRIORITY':<13}{'EPSS':<9}{'CVSS':<6}{'VERSION':<10}{'SEVERITY':<10}CISA_KEV" + \
    "\n" + ("-" * 75)
LOGO = """
  ______   ______                            
 / ___/ | / / __/                            
/ /__ | |/ / _/                              
\___/_|___/___/    __  ___         __   __   
  / _ \____(_)__  /  |/  /__ _____/ /  / /__ 
 / ___/ __/ / _ \/ /|_/ / _ `/ __/ _ \/ / -_)
/_/  /_/ /_/\___/_/  /_/\_,_/_/ /_.__/_/\__/ 

                       🔮 Version 0.0.1 🔮                                                                    
"""""


def epss_check(cve_id):
    try:
        epss_url = EPSS_URL + f"?cve={cve_id}"
        epss_response = requests.get(epss_url)
        epss_status_code = epss_response.status_code

        if epss_status_code == 200:
            if epss_response.json().get("total") > 0:
                cve_data = epss_response.json()["data"][0]
                results = {
                    "epss": float(cve_data.get("epss")),
                    "percentile": int(float(cve_data.get("percentile")) * 100),
                }
                return results
            else:
                return False
        else:
            print("Error connecting to EPSS")
    except requests.exceptions.ConnectionError:
        print("ERROR: Unable to connect to EPSS. Check your Internet connectivitiy and try again")
        return None

def nist_check(cve_id):
    try:
        nvd_key = os.getenv('NIST_API')
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        header = {'apiKey': f'{nvd_key}'} if nvd_key else {}
        nvd_response = requests.get(nvd_url, headers=header)
        nvd_status_code = nvd_response.status_code

        if nvd_status_code == 200:
            cisa_kev = False
            vulnerabilities = nvd_response.json().get("vulnerabilities")

            if vulnerabilities:
                for unique_cve in vulnerabilities:
                    if unique_cve.get("cve").get("cisaExploitAdd"):
                        cisa_kev = True

                # CVSS 4.0 https://www.first.org/cvss/v4-0/
                cvss_metric = unique_cve.get("cve").get("metrics").get("cvssMetricV31")
                cvss_version = "CVSS 3.1"
                if not cvss_metric:
                    cvss_metric = unique_cve.get("cve").get("metrics").get("cvssMetricV30")
                    cvss_version = "CVSS 3.0"
                if not cvss_metric:
                    cvss_metric = unique_cve.get("cve").get("metrics").get("cvssMetricV2")
                    cvss_version = "CVSS 2.0"

                if cvss_metric:
                    metric = cvss_metric[0]
                    results = {
                        "cvss_version": cvss_version,
                        "cvss_baseScore": float(metric.get("cvssData").get("baseScore")),
                        "cvss_severity": metric.get("cvssData").get("baseSeverity"),
                        "cisa_kev": cisa_kev,
                    }
                    return results
                elif unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                    print(
                        f"{cve_id:<18}NIST Status: {unique_cve.get('cve').get('vulnStatus')}")
            else:
                print(f"INFO: {cve_id:<18} Not Found in NIST NVD.")
        else:
            print(f"ERROR: {cve_id:<18} Error code {nvd_status_code}")
    except requests.exceptions.ConnectionError:
        print("Unable to connect to NIST NVD. Check your Internet connection or try again")
        return None


def colored_print(priority):
    colors = {
        'Priority 1+': 'red',
        'Priority 1': 'red',
        'Priority 2': 'yellow',
        'Priority 3': 'yellow',
        'Priority 4': 'green',
    }
    return colored(priority, colors.get(priority, 'white'))


def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cvss_severity, cisa_kev, verbose):
    color_priority = colored_print(priority)
    
    if verbose:
        print(f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}{cisa_kev}")
    else:
        print(f"{cve_id:<18}{color_priority:<22}")
        
    if working_file:
        working_file.write(
            f"{cve_id},{priority},{epss},{cvss_base_score},{cvss_version},{cvss_severity},{cisa_kev}\n")


def worker(cve_id, cvss_score, epss_score, verbose_print, sem, save_output=None):
    nist_result = nist_check(cve_id)
    epss_result = epss_check(cve_id)

    working_file = None
    if save_output:
        working_file = open(save_output, 'a')

    try:
        if nist_result.get("cisa_kev"):
            print_and_write(working_file, cve_id, 'Priority 1+', epss_result.get('epss'),
                            nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                            nist_result.get('cvss_severity'), 'TRUE', verbose_print)
        elif nist_result.get("cvss_baseScore") >= cvss_score:
            if epss_result.get("epss") >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 1', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print)
            else:
                print_and_write(working_file, cve_id, 'Priority 2', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print)
        else:
            if epss_result.get("epss") >= epss_score:
                print_and_write(working_file, cve_id, 'Priority 3', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print)
            else:
                print_and_write(working_file, cve_id, 'Priority 4', epss_result.get('epss'),
                                nist_result.get('cvss_baseScore'), nist_result.get('cvss_version'),
                                nist_result.get('cvss_severity'), 'FALSE', verbose_print)
    except (TypeError, AttributeError):
        pass

    if working_file:
        working_file.close()

    sem.release()


def main():
    Throttle_msg = ""
    parser = argparse.ArgumentParser(description="CVE Calculation Marble", epilog='Happy Priorization & Patching',
                                     usage='epss_calculation_marble.py -c CVE-XXXX-XXXX')
    parser.add_argument('-c', '--cve', type=str,
                        help='Unique CVE-ID', required=False, metavar='')
    parser.add_argument('-e', '--epss', type=float,
                        help='EPSS threshold (Default 0.2)', default=0.2, metavar='')
    parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='TXT file with CVEs (One per Line)',
                        required=False, metavar='')
    parser.add_argument('-n', '--cvss', type=float,
                        help='CVSS threshold (Default 6.0)', default=6.0, metavar='')
    parser.add_argument('-o', '--output', type=str,
                        help='Output filename', required=False, metavar='')
    parser.add_argument('-t', '--threads', type=int, help='Number of concurrent threads', required=False, metavar='',
                        default=100)
    parser.add_argument('-v', '--verbose',
                        help='Verbose mode', action='store_true')
    parser.add_argument('-l', '--list', help='Space separated list of CVEs',
                        nargs='+', required=False, metavar='')
    
    parser.set_defaults(func=main)

    try:
        args = parser.parse_args()
    except Exception:
        parser.print_help()

    header = SIMPLE_HEADER
    epss_threshold = args.epss
    cvss_threshold = args.cvss
    sem = Semaphore(args.threads)

    cve_list = []
    threads = []

    if args.verbose:
        header = VERBOSE_HEADER

    if args.cve:
        cve_list.append(args.cve)
        
        if not os.getenv('NIST_API'):
            print(LOGO + Throttle_msg + '\n' +
              f'WARNING: Using this tool without specifying a NIST API may result in errors. Request one at {NIST_API_KEY_REQUEST}' + '\n\n' + header)
        else:
            print(LOGO + header)
    elif args.list:
        cve_list = args.list
        if not os.getenv('NIST_API') and len(cve_list) > 75:
            Throttle_msg = "Large number of CVEs detected, requests will be throttled to avoid API issues"
        print(LOGO + Throttle_msg + '\n' + f'WARNING: Using this tool without specifying a NIST API may result in errors. Request one at {NIST_API_KEY_REQUEST}' + '\n\n' + header)
    elif args.file:
        cve_list = [line.rstrip() for line in args.file]
        if not os.getenv('NIST_API') and len(cve_list) > 75:
            Throttle_msg = "Large number of CVEs detected, requests will be throttled to avoid API issues"
        print(LOGO + Throttle_msg + '\n' + f'WARNING: Using this tool without specifying a NIST API may result in errors. Request one at {NIST_API_KEY_REQUEST}' + '\n\n' + header)

    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,cisa_kev"+"\n")

    for cve in cve_list:
        throttle = 1
        if len(cve_list) > 75 and not os.getenv('NIST_API'):
            throttle = 6
        if not re.match(r"(CVE|cve-\d{4}-\d+$)", cve):
            print(f"{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*")
        else:
            sem.acquire()
            t = threading.Thread(target=worker, args=(cve.upper().strip(), cvss_threshold, epss_threshold, args.verbose, sem, args.output))
            threads.append(t)
            t.start()
            time.sleep(throttle)

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
