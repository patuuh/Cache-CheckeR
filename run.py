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
import multiprocessing as mp
import random
import time
from datetime import datetime
from termcolor import cprint
import configparser

config = configparser.ConfigParser()
config.read("config.conf")
starttime= time.time()
x = datetime.now()
time_now = x.strftime("%d%b_%H%M")
filepath_ua = "reports/%s/user-agents" % (time_now)
filepath_hf = "reports/%s/headers" % (time_now)

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
    'Accept': '*/*'
}


error_codes = ["301", "400", "401", "403", "404", "405", "406", "500", "502", "503", "504", "520"]
no_cache_list = ["no-cache", "no-store", "'CF-Cache-Status': 'BYPASS'", "'X-Cache': 'Error from cloudfront'", "'Cache-Control': 'private", "cachepoison", "NO:Not Cacheable"]
hit_cache_list = ["'X-Check-Cacheable': 'YES'", "'CF-Cache-Status': 'HIT'", "'CF-Cache-Status': 'MISS'", "'X-Cache': 'MISS'" "'X-Cache': 'HIT'", "'CF-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'DYNAMIC'", "'X-Fastcgi-Cache-Status': 'HIT'", "'X-Fastcgi-Cache-Status': 'MISS'",]
cacheable_list = ["HIT", "MISS", "DYNAMIC", "STALE", "cache-status: EXPIRED", "BYPASS"]
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
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--uafile",
                    dest="user_agent_file",
                    help="user_agent fuzzing list - [default: default_list.txt].",
                    default="default_list.txt",
                    action='store')
parser.add_argument("--headersfile",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--all",
                    dest="all",
                    help="Enable all tests",
                    action='store_true')
parser.add_argument("--headers","-hf",
                    dest="headers_fuzz",
                    help="Enable headers fuzzing",
                    action='store_true')
parser.add_argument("--useragents","-ua",
                    dest="user_agent_fuzz",
                    help="Enable user-agent fuzzing",
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
parser.add_argument("--verbose","-v",
                    dest="verbose",
                    help="Verbose print",
                    action='store_true')
parser.add_argument("--cache-checker","-cc",
                    dest="checker",
                    help="Automatically checks bug bounty platforms urls and scans for their caching headers",
                    action='store_true')

args = parser.parse_args()

class KeyboardInterruptError(Exception): pass

def ua_scan_url(url, q):
    baseline_useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0)"

    # Try baseline header to verify if cache is poisoned
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    fuzzing_headers.update({'User-Agent':baseline_useragent})
    
    print("Starting user-agent scan to url: " + url + "...\n")
    try:
        x = requests.request(url=url + "?avoid_poison=test",
                            method="GET",
                            headers=fuzzing_headers,
                            verify=False,
                            timeout=timeout,
                            allow_redirects=True)
        x = requests.request(url=url + "?avoid_poison=test",
                            method="GET",
                            headers=fuzzing_headers,
                            verify=False,
                            timeout=timeout,
                            allow_redirects=True)
    except Exception as e:
        cprint(f"EXCEPTION: {e}")
        return
    if args.verbose:
        print("URL: " + url + "?avoid_poison=test\nBaseline request:\nResponse status code: " + str(x.status_code) + "\nResponse headers: " + str(x.headers))
    
    
    if str(x.status_code) in error_codes:
        cprint(f"[UA] Got error: " + str(x.status_code) + " with baseline header", "yellow")
        cprint(f"[UA] Skipping to the next host...\n", "yellow")
        return
        
    baseline_status_code = str(x.status_code)
    baseline_headers = str(x.headers)
    baseline_length = len(x.content)

    try:
        with open(args.user_agent_file, "r") as f:
            for i in f.readlines():
                if args.rate:
                    time.sleep(args.rate)
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                if args.custom_user:
                    i = i + " - " + args.custom_user
                fuzzing_headers = {}
                fuzzing_headers.update(default_headers)
                fuzzing_headers.update({'User-Agent':i})
                x = ""
                random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
                fuzzing_headers.update({'Origin':random_string})
                if "?" in url:
                    fuzz_url = url + "&avoid_poison=" + random_string
                else:
                    fuzz_url = url + "?avoid_poison=" + random_string
                if args.request_type.upper() == "GET":
                    try:
                        x = requests.request(url=fuzz_url,
                                            method="GET",
                                            headers=fuzzing_headers,
                                            verify=False,
                                            timeout=timeout,
                                            allow_redirects=True)
                    except Exception as e:
                        cprint(f"EXCEPTION: {e}")
                        break

                if args.request_type.upper() == "POST":
                    try:
                        # Post body
                        x = requests.request(url=fuzz_url,
                                            method="POST",
                                            headers=fuzzing_headers,
                                            verify=False,
                                            timeout=timeout,
                                            allow_redirects=True)
                    except Exception as e:
                        if "Exceeded 30 redirects" in str(e):
                            cprint(f"EXCEPTION: {e}")
                            continue
                        cprint(f"EXCEPTION: {e}")
                        break
                try:
                    if str(x.status_code) == "429":
                        cprint(f"[UA] Hit the rate limit with host: " + url, "yellow")
                        cprint(f"[UA] Skipping to the next host...\n", "yellow")
                        break

                    save_status_code = str(x.status_code)
                    save_response_headers = str(x.headers)
                    save_fuzz_headers = str(fuzzing_headers)
                    save_len = len(x.content)
                    
                    if str(x.status_code) != "200":
                        cprint(f"[UA] URL: {fuzz_url}", "yellow")
                        cprint(f"[UA] Status: " + str(x.status_code), "yellow")
                        cprint(f"[UA] Trying with baseline request to see if poisoned\n", "yellow")
                        if args.verbose:
                            print("Request headers: " + str(save_fuzz_headers) + "\nResponse headers: " + str(x.headers))
                        
                        # Try baseline UA to verify if cache is poisoned
                        fuzzing_headers = {}
                        fuzzing_headers.update(default_headers)
                        fuzzing_headers.update({'User-Agent':baseline_useragent})
                        fuzzing_headers.update({'Origin':random_string})
                        try:
                            x = requests.request(url=fuzz_url,
                                                method="GET",
                                                headers=fuzzing_headers,
                                                verify=False,
                                                timeout=timeout,
                                                allow_redirects=True)
                        except Exception as e:
                            if "Exceeded 30 redirects" in str(e):
                                cprint(f"EXCEPTION: {e}")
                                continue
                            cprint(f"EXCEPTION: {e}")
                            break
                        
                        if str(x.status_code) == save_status_code:
                            len_difference = abs(baseline_length - save_len)
                            cprint(f"[UA] URL: {fuzz_url}", "red")
                            cprint(f"[UA] Possibly vulnerable! Baseline status code: " + str(x.status_code), "red")
                            cprint(f"[UA] Check results file", "red")
                            cprint(f"[UA] Continuing to next host\n", "yellow")
                            path_url = url.replace("https://", "")
                            path_url = path_url.replace("/", "")
                            path_url = path_url.replace("%", "")
                            path_url = path_url.replace("?", "")
                            resultsPath = filepath_ua + "/" + str(x.status_code) + "_"  + path_url + "_useragent_results.txt"
                            writer = open(resultsPath, "a")
                            writer.write("Possibly poisoned!!!!\nCheck following url:")
                            writer.write(fuzz_url + " | These headers were used: " + str(save_fuzz_headers) + "\nResponse status code: " + save_status_code + "\n")
                            writer.write("Response headers: " + str(x.headers) + "\nLength difference: " + str(len_difference) + "\n")
                            writer.write("Fuzzer length: " + str(save_len) + "\nBaseline test length : " + str(baseline_length) + "\n")
                            message = "Host possibly poisoned!\n\nURL: " + fuzz_url + "\n\nResponse status code: " + str(x.status_code) + "\n\nThese headers were used:\n" + str(save_fuzz_headers)
                            send_msg(message)
                            if args.url:
                                continue
                            else:
                                break
                        else:
                            cprint(f"[UA] URL: {fuzz_url}", "yellow")
                            cprint(f"[UA] Baseline request normal, no poison: " + str(x.status_code) + "\n", "yellow")
                            continue


                    if str(x.status_code) == "200":
                        len_difference = abs(baseline_length - len(x.content))
                        if str(x.headers) not in no_cache_list and len_difference > 5000:
                        #if str(x.headers) not in no_cache_list and len(x.content) < 500:
                            cprint(f"[UA] URL: {fuzz_url}", "yellow")
                            cprint(f"[UA] Status: " + str(x.status_code), "yellow")
                            if args.verbose:
                                print("Request headers: " + str(save_fuzz_headers) + "\nResponse headers: " + str(x.headers))
                            cprint(f"[UA] Trying with baseline headers to see if poisoned\n", "yellow")
                            # Try baseline UA to verify if cache is poisoned
                            save_len = len(x.content)
                            fuzzing_headers = {}
                            fuzzing_headers.update(default_headers)
                            fuzzing_headers.update({'User-Agent':baseline_useragent})
                            fuzzing_headers.update({'Origin':random_string})
                            try:
                                x = requests.request(url=fuzz_url,
                                                    method="GET",
                                                    headers=fuzzing_headers,
                                                    verify=False,
                                                    timeout=timeout,
                                                    allow_redirects=True)
                            except Exception as e:
                                if "Exceeded 30 redirects" in str(e):
                                    cprint(f"EXCEPTION: {e}")
                                    continue
                                cprint(f"EXCEPTION: {e}")
                                break
                            # Compare response lengths and if responses differ under 50 bytes, report
                            len_difference2 = abs(save_len - len(x.content))
                            if str(x.status_code) == save_status_code and len_difference2 < 50:
                                cprint(f"[UA] URL: {fuzz_url}", "red")
                                cprint(f"[UA] Possibly vulnerable! Baseline status code: " + str(x.status_code), "red")
                                cprint(f"[UA] Check results file", "red")
                                cprint(f"[UA] Continuing to next host\n", "yellow")
                                path_url = url.replace("https://", "")
                                path_url = path_url.replace("/", "")
                                path_url = path_url.replace("%", "")
                                path_url = path_url.replace("?", "")
                                resultsPath = filepath_ua + "/" + str(x.status_code) + "_" + path_url + "_useragent_results.txt"
                                writer = open(resultsPath, "a")
                                writer.write("Possibly poisoned!!!!\nCheck following url:")
                                writer.write(fuzz_url + " | These headers were used: " + str(save_fuzz_headers) + "\nResponse status code: " + save_status_code + "\n")
                                writer.write("Response headers: " + str(x.headers) + "\nLength difference: " + str(len_difference) + "\n")
                                writer.write("Fuzzer length: " + str(save_len) + "\nBaseline test length : " + str(baseline_length) + "\n")
                                message = "Host possibly poisoned!\n\nURL: " + fuzz_url + "\n\nResponse status code: " + str(x.status_code) + "\n\nThese headers were used:\n" + str(save_fuzz_headers)
                                send_msg(message)
                                if args.url:
                                    continue
                                else:
                                    cprint(f"[UA] Continuing to next host\n", "yellow")
                                    break
                            else:
                                cprint(f"[UA] URL: {fuzz_url}", "yellow")
                                cprint(f"[UA] Baseline request normal, no poison: " + str(x.status_code) + "\n", "yellow")
                                continue
                        continue
                        
                except Exception as e:
                        cprint(f"EXCEPTION: {e}")
    except KeyboardInterrupt:
        raise KeyboardInterruptError()

def headers_scan_url(url, q):
    header_value = "azazazazazaza"
    baseline_header = "test"
    default_headers = {
    'Accept': '*/*',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0)'
    }
    # Try baseline header to verify if cache is poisoned
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    fuzzing_headers.update({baseline_header:header_value})
    print("Starting header scan to url: " + url + "...\n")
    try:
        x = requests.request(url=url + "?zzz=123",
                            method="GET",
                            headers=fuzzing_headers,
                            verify=False,
                            timeout=timeout,
                            allow_redirects=True)
        x = requests.request(url=url + "?zzz=123",
                            method="GET",
                            headers=fuzzing_headers,
                            verify=False,
                            timeout=timeout,
                            allow_redirects=True)
    except Exception as e:
        cprint(f"EXCEPTION: {e}")
        return
    if args.verbose:
        print("URL: " + url + "?zzz=123\nBaseline request headers: " + str(fuzzing_headers) + "\nResponse status code: " + str(x.status_code) + "\nResponse headers: " + str(x.headers) + "\n")
    
    if str(x.status_code) in error_codes:
        cprint(f"[H] Got error: " + str(x.status_code) + " with baseline header", "yellow")
        cprint(f"[H] Skipping to the next host...\n", "yellow")
        return
        
    baseline_status_code = str(x.status_code)
    baseline_headers = str(x.headers)
    baseline_length = len(x.content)

    try:
        with open(args.headers_file, "r") as f:
            break_flag = False
            for i in f.readline():
                fuzzing_headers = {}
                fuzzing_headers.update(default_headers)
                for a in range(15):
                    line = f.readline()
                    if line == '':
                        break_flag = True
                        break
                    line = line.strip()
                    if line == "" or line.startswith("#"):
                        continue
                    if args.custom_user:
                        fuzzing_headers.update({"User-Agent": args.custom_user})
                    if ":" in line:
                        header_splitted = line.split(":")
                        h1 = header_splitted[0]
                        h2 = header_splitted[1].replace(" ", "")
                        fuzzing_headers.update({str(h1): str(h2)})
                    else:
                        fuzzing_headers.update({line:header_value})
                random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
                fuzzing_headers.update({'Origin':random_string})
                if "?" in url:
                    dist_url = url + "&zzz=" + random_string
                else:
                    dist_url = url + "?zzz=" + random_string
                x = ""
                if args.verbose:
                    print("Request headers: " + str(fuzzing_headers))
                try:
                    x = requests.request(url=dist_url,
                                        method="GET",
                                        headers=fuzzing_headers,
                                        verify=False,
                                        timeout=timeout,
                                        allow_redirects=True)
                except Exception as e:
                    if "Exceeded 30 redirects" in str(e):
                        cprint(f"EXCEPTION: {e}")
                        continue
                    cprint(f"EXCEPTION: {e}")
                    break

                try:
                    if str(x.status_code) == "429":
                        cprint(f"[H] Hit the rate limit with host: " + url, "yellow")
                        cprint(f"[H] Skipping to the next host...\n", "yellow")
                        break

                    save_status_code = str(x.status_code)
                    save_headers = str(fuzzing_headers)
                    
                    if str(x.status_code) != "200":
                        cprint(f"[H] URL: {dist_url}", "yellow")
                        cprint(f"[H] Status: " + str(x.status_code), "yellow")
                        if args.verbose:
                            print("Request headers: " + str(save_headers) + "\nResponse headers: " + str(x.headers))
                        cprint(f"[H] Trying with baseline headers to see if poisoned\n", "yellow")
                        # Try baseline header to verify if cache is poisoned
                        fuzzing_headers = {}
                        fuzzing_headers.update(default_headers)
                        fuzzing_headers.update({baseline_header:header_value})
                        fuzzing_headers.update({'Origin':random_string})
                        try:
                            x = requests.request(url=dist_url,
                                                method="GET",
                                                headers=fuzzing_headers,
                                                verify=False,
                                                timeout=timeout,
                                                allow_redirects=True)
                        except Exception as e:
                            cprint(f"EXCEPTION: {e}")
                            break
                        if str(x.status_code) == save_status_code:
                            cprint(f"[H] URL: {dist_url}", "red")
                            cprint(f"[H] Possibly vulnerable! Baseline status code: " + str(x.status_code), "red")
                            cprint(f"[H] Check results file\n", "red")
                            path_url = url.replace("https://", "")
                            path_url = path_url.replace("/", "")
                            path_url = path_url.replace("%", "")
                            path_url = path_url.replace("?", "")
                            resultsPath = filepath_hf + "/" + str(x.status_code) + "_"  + path_url + "_header_results.txt"
                            writer = open(resultsPath, "a")
                            writer.write("Possibly poisoned!!!!\nCheck following url:")
                            writer.write(dist_url + " | These headers were used: " + str(save_headers) + "\nResponse status code: " + str(x.status_code) + "\n")
                            writer.write("Response headers: " + str(x.headers) + "\n\n")
                            message = "Host possibly poisoned!\n\nURL: " + dist_url + "\n\nResponse status code: " + str(x.status_code) + "\n\nThese headers were used:\n" + str(save_headers)
                            send_msg(message)
                            if args.url:
                                continue
                            else:
                                break
                        else:
                            cprint(f"[H] URL: {dist_url}", "yellow")
                            cprint(f"[H] Baseline request normal, no poison: " + str(x.status_code) + "\n", "yellow")
                            continue


                    if str(x.status_code) == "200":
                        len_difference = abs(baseline_length - len(x.content))
                        if str(x.headers) not in no_cache_list and len_difference > 5000:
                        #if str(x.headers) not in no_cache_list and len(x.content) < 500:
                            save_len = len(x.content)
                            cprint(f"[H] URL: {dist_url}", "yellow")
                            cprint(f"[H] Status: " + str(x.status_code), "yellow")
                            if args.verbose:
                                print("Request headers: " + str(save_headers) + "\nResponse headers: " + str(x.headers))
                            cprint(f"[H] Trying with baseline headers to see if poisoned\n", "yellow")
                            # Try baseline header to verify if cache is poisoned
                            fuzzing_headers = {}
                            fuzzing_headers.update(default_headers)
                            fuzzing_headers.update({baseline_header:header_value})
                            fuzzing_headers.update({'Origin':random_string})
                            try:
                                x = requests.request(url=dist_url,
                                                    method="GET",
                                                    headers=fuzzing_headers,
                                                    verify=False,
                                                    timeout=timeout,
                                                    allow_redirects=True)
                            except Exception as e:
                                if "Exceeded 30 redirects" in str(e):
                                    cprint(f"EXCEPTION: {e}")
                                    continue
                                cprint(f"EXCEPTION: {e}")
                                break
                            # Compare response lengths and if responses differ under 50 bytes, report
                            len_difference2 = abs(save_len - len(x.content))
                            if str(x.status_code) == save_status_code and len_difference2 < 50:
                                cprint(f"[H] Possibly vulnerable! Baseline status code: " + str(x.status_code), "red")
                                cprint(f"[H] Check results file", "red")
                                cprint(f"[H] Continuing to next host\n", "yellow")
                                path_url = url.replace("https://", "")
                                path_url = path_url.replace("/", "")
                                path_url = path_url.replace("%", "")
                                path_url = path_url.replace("?", "")
                                resultsPath = filepath_hf + "/" + str(x.status_code) + "_" + path_url + "_header_results.txt"
                                writer = open(resultsPath, "a")
                                writer.write("Possibly poisoned!!!!\nCheck following url:")
                                writer.write(dist_url + " | These headers were used: " + str(save_headers) + "\nResponse status code: " + str(x.status_code) + "\n")
                                writer.write("Response headers: " + str(x.headers) + "\nLength difference: " + str(len_difference) + "\n")
                                writer.write("Fuzzer length: " + str(save_len) + "\nBaseline test length : " + str(baseline_length) + "\n\nBaseline headers:\n" + str(baseline_headers) + "\n\n")
                                message = "Host possibly poisoned!\n\nURL: " + dist_url + "\n\nResponse status code: " + str(x.status_code) + "\n\nThese headers were used:\n" + str(save_headers)
                                send_msg(message)
                                if args.url:
                                    continue
                                else:
                                    break
                            else:
                                cprint(f"[H] Baseline request normal, no poison: " + str(x.status_code) + "\n", "yellow")
                                continue
                        continue
                                                    
                except Exception as e:
                        cprint(f"EXCEPTION: {e}")
                if break_flag:
                    break
    except KeyboardInterrupt:
        raise KeyboardInterruptError()

def send_msg(msg):

    TOKEN = config.get("Telegram", "Token")
    chat_id = config.get("Telegram", "chat_id")

    message = msg
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    print(requests.get(url).json()) # this sends the message

def main():
    if not args.headers_fuzz and not args.user_agent_fuzz and not args.all:
        cprint(f'\nYou need to have at least one fuzzer enabled:', "red")
        cprint(f'[USER-AGENT FUZZING: -ua]\n[HEADERS FUZZING: -hf]\n[FUZZ HEADERS & USER-AGENT: --all]', "green")
        exit(0)
    urls = []
    if args.url:
        if ('://' not in args.url):
            args.url = str("https://") + str(args.url)
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            #for i in reversed(f.readlines()):
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                if ('://' not in i):
                    i = str("https://") + str(i)
                urls.append(i)
    if args.checker:
        os.system("python3 .\\Cache-Checker\\run.py -bb")
        with open("found_urls.txt", "r") as f:
            #for i in reversed(f.readlines()):
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#") or i.endswith("."):
                    continue
                if ('://' not in i):
                    i = str("https://") + str(i)
                urls.append(i)

    x = datetime.now()
    time_now = x.strftime("%d%b_%H%M")
    global filepath_hf
    global filepath_ua
    filepath_ua = "reports/%s/user-agents" % (time_now)
    filepath_hf = "reports/%s/headers" % (time_now)
    
    if "Win" in platform.system():
        os.system("mkdir %s" % (os.path.normpath(filepath_hf)))
        os.system("mkdir %s" % (os.path.normpath(filepath_ua)))
    else:
        os.system("mkdir -p %s" % (filepath_hf))
        os.system("mkdir -p %s" % (filepath_ua))
    try:
        manager = mp.Manager()
        q = manager.Queue()    
        pool = mp.Pool(mp.cpu_count() + 2)
        jobs = []
        for url in urls:
            if args.user_agent_fuzz:
                cprint(f"[•] Starting User-agent scan\n", "green")
                job = pool.apply_async(ua_scan_url, (url, q))
                jobs.append(job)
                cprint(f"[•] User-agent scan finished\n", "green")
            if args.headers_fuzz:
                cprint(f"[•] Starting headers scan\n", "green")
                job = pool.apply_async(headers_scan_url, (url, q))
                jobs.append(job)
                cprint(f"[•] Headers scan finished\n", "green")
            if args.all:
                
                cprint(f"[•] Starting User-agent scan\n", "green")
                job = pool.apply_async(ua_scan_url, (url, q))
                jobs.append(job)
                cprint(f"[•] User-agent scan finished\n", "green")
                cprint(f"[•] Starting headers scan\n", "green")
                job = pool.apply_async(headers_scan_url, (url, q))
                jobs.append(job)
                cprint(f"[•] Headers scan finished\n", "green")

        # collect results from the workers through the pool result queue
        for job in jobs: 
            job.get()

        #now we are done, kill the listener
        q.put('kill')
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt Detected.")
        print("Exiting...")
        pool.terminate()
        pool.join()
        exit()

if __name__ == "__main__":
    main()
    
