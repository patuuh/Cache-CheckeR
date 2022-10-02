#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# Author:
# Patuuh
# 
# ******************************************************************

import argparse
import random
import requests
import time
import platform
import os
import sys
import time
from urllib import parse as urlparse
import random
import time
from datetime import datetime
from termcolor import cprint

starttime= time.time()

x = datetime.now()
time_now = x.strftime("%d%b_%H%M")
filepath = "reports/%s" % (time_now)

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

cprint('[•] Scanner provided by KeiZo', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)

default_headers = {
    'BugBounty': 'BUG_BOUNTY_USER',
    'Accept': '*/*'
}

error_codes = ["301", "400", "401", "403", "404", "405", "406", "500", "502", "504", "520"]
no_cache_list = ["no-cache", "no-store", "'CF-Cache-Status': 'BYPASS'", "'X-Cache': 'Error from cloudfront'", "'Cache-Control': 'private", "cachepoison"]
hit_cache_list = ["'X-Check-Cacheable': 'YES'", "'CF-Cache-Status': 'HIT'", "'CF-Cache-Status': 'MISS'", "'X-Cache': 'MISS'" "'X-Cache': 'HIT'", "'CF-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'HIT'", "'X-Fastcgi-Cache-Status': 'MISS'",]
words = ["HIT", "MISS", "DYNAMIC", "STALE", "cache-status: EXPIRED", "BYPASS"]
any_cache_word_list = ["cache", "Cache"]
timeout = 5

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("-bb", "--bug-bounty",
                    dest="bb_list",
                    help="Use bug bounty list for URLs to scan.",
                    action='store_true')
parser.add_argument("--all",
                    dest="all",
                    help="Enable all tests",
                    action='store_true')
parser.add_argument("--verbose","-v",
                    dest="verbose",
                    help="Verbose print",
                    action='store_true')
parser.add_argument("-cu",
                    dest="custom_user",
                    help="Custom User-Agent append (For example if bug bounty program wants spesific user-agent to be present)",
                    action='store')
parser.add_argument("--rate",
                    dest="rate",
                    help="Rate-limit. Use slower rate. Default 250 ms if this is present",
                    const=0.25, 
                    type=int,
                    nargs='?')

args = parser.parse_args()



def scan_url(url):
    #useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0)"
    resultsPath = filepath + "/results.txt"
    url_list_path = filepath + "/found_urls.txt"

    writer = open(resultsPath, "a")
    url_writer = open(url_list_path, "a")
    
    

    if args.verbose:
        verbosepath = filepath + "/verbose_Results.txt"
        verbosewriter = open(verbosepath, "a")

    
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
    #fuzz_url = url + "?avoid_poison=" + random_string
    fuzz_url = url
    try:
        x = requests.request(url=fuzz_url,
                            method="GET",
                            headers=fuzzing_headers,
                            verify=False,
                            timeout=timeout,
                            allow_redirects=True)
    except Exception as e:
        cprint(f"EXCEPTION: {e}")
        return

    if str(x.status_code) != "200":
        cprint(f"[•] Not 200 - OK status code received: " + str(x.status_code) + ". Check for correct url!", "yellow")
        writer.write(fuzz_url + "\nStatus code: " + str(x.status_code) + " received! Check for correct url!\n\n")

    if(any(ele in str(x.headers) for ele in words)):
        cprint(f"[•] Cache headers spotted: " + str(x.headers), "red")
        cprint(f"[•] Saving to file...", "red")
        writer.write(fuzz_url + "\n" + str(x.headers) + "\n\n")
        url_writer.write(fuzz_url + "\n")
    else:
        cprint(f"[•] No wanted caching headers found", "white")
        cprint(f"[•] Continuing to next host...", "white")
        return
                    

def main():
    if args.bb_list:
        if not os.path.isdir('bounty-targets-data'):
            # First time run
            os.system('git clone https://github.com/arkadiyt/bounty-targets-data.git')
        else:
            # Not first time run
            os.system('cd bounty-targets-data && git pull')  

    urls = []
    if args.url:
        if ('://' not in args.url):
            args.url = str("https://") + str(args.url)
        urls.append(args.url)
    if args.usedlist or args.bb_list:
        if args.usedlist:
            url_list = args.usedlist
        else:    
            url_list = "bounty-targets-data/data/domains.txt"
        with open(url_list, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                if ('://' not in i):
                    i = str("https://") + str(i)
                urls.append(i)

    try:
        for url in urls:
            cprint(f"[•] URL: {url}", "magenta")
            scan_url(url)
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt Detected.")
        print("Exiting...")
        exit(0)



if __name__ == "__main__":
    if "Win" in platform.system():
        os.system("mkdir %s" % (os.path.normpath(filepath)))
    else:
        os.system("mkdir -p %s" % (filepath))
    main()
