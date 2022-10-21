#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# Author:
# Patuuh
# 
#
# TODO: Check that additional host is in scope
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
from bs4 import BeautifulSoup
import configparser

starttime= time.time()
config = configparser.ConfigParser()
config.read("config.conf")

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
    'BugBounty': 'KeiZo',
    'Accept': '*/*'
}

error_codes = ["301", "400", "401", "403", "404", "405", "406", "500", "502", "504", "520"]
no_cache_list = ["no-cache", "no-store", "'CF-Cache-Status': 'BYPASS'", "'X-Cache': 'Error from cloudfront'", "'Cache-Control': 'private", "cachepoison"]
hit_cache_list = ["'X-Check-Cacheable': 'YES'", "'CF-Cache-Status': 'HIT'", "'CF-Cache-Status': 'MISS'", "'X-Cache': 'MISS'" "'X-Cache': 'HIT'", "'CF-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'HIT'", "'X-Fastcgi-Cache-Status': 'MISS'",]
words = ["HIT", "MISS", "DYNAMIC", "STALE", "cache-status: EXPIRED", "BYPASS"]
any_cache_word_list = ["cache", "Cache"]
timeout = 5
cacheable_found = False

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

args = parser.parse_args()



def scan_url(url, recursive_flag):
    #useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0)"
    resultsPath = filepath + "/results.txt"
    #url_list_path = filepath + "/found_urls.txt"
    url_list_path = "found_urls.txt"

    writer = open(resultsPath, "a")
    url_writer = open(url_list_path, "a")
    

    
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
        global cacheable_found
        cacheable_found = True
    else:
        cprint(f"[•] No wanted caching headers found", "white")
        cprint(f"[•] Continuing to next host...", "white")
        
    if not recursive_flag:
        try:
            soup = BeautifulSoup(str(x.content), "html.parser")
            link = soup.find('link')
            additional_url = link.get('href')
            if url not in additional_url: # If another host found than the original host, try to find next link
                link = soup.findNext('link')
                additional_url = link.get('href')
            if url not in additional_url: # If another host found again than the original host, return
                return
            cprint(f"[•] Additional url found...", "white")
            if ".." in additional_url:
                additional_url = additional_url.replace("..", "")
            if "https://" in additional_url:
                new_url = additional_url
            else:
                new_url = url + additional_url
            cprint(f"[•] Starting scan to: " + new_url, "white")
        except Exception as e:
            cprint(f"EXCEPTION: {e}")
            return
        scan_url(new_url, True)

def send_msg(msg):

    TOKEN = config.get("Telegram", "Token")
    chat_id = config.get("Telegram", "chat_id")

    message = msg
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    requests.get(url).json() # this sends the message

def url_diff():
    domains = open("bounty-targets-data/data/domains.txt", "r")
    domains_old = open("bounty-targets-data/data/domains_old.txt", "r")
    diff_urls = open("diff_urls.txt", "w+") # URLs that are newly added

    old_lines = domains_old.read().splitlines()
    new_lines = domains.read().splitlines()
    new_flag = False
    url_list_message = "New urls found: \n"
    for new_line in new_lines:
        if new_line in old_lines:
            continue
        else:
            print("found new url: " + new_line)
            new_flag = True
            diff_urls.write(new_line + "\n")
            url_list_message = url_list_message + str(new_line) + "\n"
    if new_flag:
        send_msg(url_list_message)
    url_file = "diff_urls.txt" 

    return url_file, new_flag     

def main():
    url_list_path = "found_urls.txt"
    url_writer = open(url_list_path, "w") # Empty the file
    url_writer.close()
    if args.bb_list:
        while True:    
            if not os.path.isdir('bounty-targets-data'):
                # First time run
                new_flag = True
                os.system('git clone https://github.com/arkadiyt/bounty-targets-data.git')
                url_file = "bounty-targets-data/data/domains.txt"
                break
            else:
                # Not first time run
                os.system('cd bounty-targets-data && cp data/domains.txt data/domains_old.txt && git pull')
                #os.system('cd bounty-targets-data && cp data/domains.txt data/domains_old.txt')   
                url_file,new_flag = url_diff() 

            if new_flag == False:
                print("No new hosts found!")
                print("Scanning again in 30 minutes!")
                time_now = str(datetime.now().strftime('%d-%m-%Y %H:%M:%S')[:-3])
                print("Time now: " + time_now)
                time.sleep(1800)
                continue
            else:
                break
    
    x = datetime.now()
    time_now = x.strftime("%d%b_%H%M")
    global filepath 
    filepath = "reports/%s" % (time_now)
    
    if "Win" in platform.system():
        os.system("mkdir %s" % (os.path.normpath(filepath)))
    else:
        os.system("mkdir -p %s" % (filepath))

    urls = []
    if args.url:
        if ('://' not in args.url):
            args.url = str("https://") + str(args.url)
        urls.append(args.url)
    if args.usedlist or args.bb_list:
        if args.usedlist:
            url_list = args.usedlist
        else:    
            url_list = url_file
        with open(url_list, "r") as f:
            #for i in reversed(f.readlines()):
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
            scan_url(url, False)
        if cacheable_found:
            diff_urls = open("found_urls.txt", "r") # URLs that are newly added
            new_lines = diff_urls.read()
            message = "New hosts with caching headers found:\n" + new_lines
            send_msg(message)

    except KeyboardInterrupt:
        print("\nKeyboard Interrupt Detected.")
        print("Exiting...")
        exit(0)



if __name__ == "__main__":

    if sys.version_info[0] < 3:
        raise Exception("You need to use Python3")
        
    main()
