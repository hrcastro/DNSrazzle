#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|

Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2023 SecurityShrimp

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

__version__ = '1.5.4'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

import argparse
import csv
import os
import signal
import sys
import time
from progress.bar import Bar
from dnsrazzle import IOUtil
from dnsrazzle.DnsRazzle import DnsRazzle
from dnsrazzle.IOUtil import print_error, print_good, print_status


def main():
    os.environ['WDM_LOG_LEVEL'] = '0'
    IOUtil.banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--blocklist', action="store_true", dest='blocklist', default=False,
                        help="Generate a blocklist of domains/IP addresses of suspected impersonation domains.")
    parser.add_argument('-B', '--blocklist_pct', type=float, dest='blocklist_pct', metavar='PCT', default=0.9,
                        help="Threshold for what gets put on the blocklist. Default is 0.9.")
    parser.add_argument('--browser', type=str, dest='browser', default='chrome',
                        help='Specify browser to use with WebDriver. Default is "chrome", "firefox" is also supported.')
    parser.add_argument('-d', '--domain', type=str, dest='domain', help='Target domain or domain list.')
    parser.add_argument('-D', '--dictionary', type=str, dest='dictionary', metavar='FILE', default=[],
                        help='Path to dictionary file to pass to DNSTwist to aid in domain permutation generation.')
    parser.add_argument('-e', '--email', dest='email', action='store_true', default=False,
                        help='Tell DNSRazzle to email the reports when completed. Requires configuration in etc/mail_config.conf.')
    parser.add_argument('-f', '--file', type=str, dest='file', metavar='FILE', default=None,
                        help='Provide a file containing a list of domains to run DNSrazzle on.')
    parser.add_argument('-g', '--generate', dest='generate', action='store_true', default=False,
                        help='Do a dry run of DNSRazzle and just output permutated domain names.')
    parser.add_argument('-n', '--nmap', dest='nmap', action='store_true', default=False,
                        help='Perform nmap scan on discovered domains.')
    parser.add_argument('-N', '--nameservers', metavar='STRING', type=str, default='1.1.1.1,1.0.0.1',
                        help='Comma-separated list of DNS nameservers to use for DNS queries.')
    parser.add_argument('--noss', dest='no_screenshot', action='store_true',
                        help='Do not take screenshots of discovered domains. Only collect DNS and banner info.')
    parser.add_argument('--nowhois', dest='no_whois', action='store_true', default=False,
                        help='Do not run whois for discovered domains.')
    parser.add_argument('-o', '--out-directory', type=str, dest='out_dir', default=None,
                        help='Absolute path of directory to output reports to. Will be created if doesn\'t exist.')
    parser.add_argument('--justTestLogoDetection', dest='justTestLogoDetection', action='store_true', default=False,
                        help='Test the process for 1 url only.')
    parser.add_argument('-r', '--recon', dest = 'recon', action = 'store_true', default = False,
                        help = 'Create dnsrecon report on discovered domains.')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=10,
                        help='Number of threads to use in permutation checks, reverse lookups, forward lookups, brute force and SRV record enumeration.')
    parser.add_argument('--tld', type=str, dest='tld', metavar='FILE', default=[],
                        help='Path to TLD dictionary file.')
    parser.add_argument('--yolo', type=str, dest='yolo', metavar='FILE', default=[],
                        help='Path to YOLO weights file (best.pt)')
    parser.add_argument('--nointeractive', dest='no_interactive', action='store_true', default=False,
                        help='Use standard prints to show progress, intead of user progress Bars.')
    parser.add_argument('-u', '--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnsrazzle/%s' % __version__,
                        help='User-Agent STRING to send with HTTP requests. Default is Mozilla/5.0 dnsrazzle/%s)' % __version__)
    parser.add_argument('--debug', dest='debug', action='store_true', default=False, help='Print debug messages')
    arguments = parser.parse_args()

    out_dir = arguments.out_dir
    useragent = arguments.useragent
    threads = arguments.threads
    debug = arguments.debug
    justPrintDomains = arguments.generate
    nmap = arguments.nmap
    recon = arguments.recon
    email = arguments.email
    no_screenshot = arguments.no_screenshot
    no_whois = arguments.no_whois
    no_interactive = arguments.no_interactive
    driver = None
    justTestLogoDetection = arguments.justTestLogoDetection

    nameservers = arguments.nameservers.split(',')

    def signal_handler(signal, frame):
        print(f'\nStopping threads... ', file=sys.stderr, end='', flush=True)
        for worker in razzle.workers:
            worker.stop()
            worker.join()
        print(f'Done', file=sys.stderr)
        _exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if debug:
        os.environ['WDM_LOG_LEVEL'] = '4'

    if arguments.domain is not None:
         domain_raw_list = list(set(arguments.domain.split(",")))
    elif arguments.file is not None:
         domain_raw_list = []
         with open(arguments.file) as f:
            for item in f.read().splitlines():
                domain_raw_list.append(item)
    else:
         print_error(f"You must specify either the -d or the -f option")
         sys.exit(1)

    if not arguments.generate:
        if out_dir is None:
            out_dir =  os.getcwd()
        print_status(f"Saving records to output folder {out_dir}")
        IOUtil.create_folders(out_dir, nmap, recon)

    dictionary = []
    if arguments.dictionary:
        if not os.path.exists(arguments.dictionary):
            parser.error('dictionary file not found: %s' % arguments.dictionary)
        with open(arguments.dictionary) as f:
            dictionary = set(f.read().splitlines())
            dictionary = [x for x in dictionary if x.isalnum()]

    tld = []
    if arguments.tld:
        if not os.path.exists(arguments.tld):
            parser.error('dictionary file not found: %s' % arguments.tld)
        with open(arguments.tld) as f:
            tld = set(f.read().splitlines())
            tld = [x for x in tld if x.isalpha()]

    razzles: list[DnsRazzle] = []
    if no_interactive:
        print_status(f"Generating possible domain name impersonations…")
    else:
        bar = Bar(f'Generating possible domain name impersonations…', max=len(domain_raw_list))
    for entry in domain_raw_list:
        razzle = DnsRazzle(domain=str(entry), out_dir=out_dir, tld=tld, dictionary=dictionary, file=arguments.file,
                useragent=useragent, debug=True, threads=threads, nmap=nmap, recon=recon, driver=driver,
                nameservers=nameservers)
        if not justTestLogoDetection:
            razzle.generate_fuzzed_domains()
        else:
            razzle.domains = [{"domain-name": razzle.domain}]
        razzles.append(razzle)
        if no_interactive:
            print_status(f"Generated possible domain name impersonations for {razzle.domain}")
        else:
            bar.next()
    if no_interactive:
        print_good(f"Generated possible domain name impersonations for {len(domain_raw_list)} domains")
    else:
        bar.finish()

    if justPrintDomains:
        for razzle in razzles:
            for entry in razzle.domains[1:]:
                print(entry['domain-name'])
        return

    for razzle in razzles:
        if no_interactive:
            print_status(f"Generating DNS lookup of possible domain permutations for {razzle.domain}…")
        else:
            bar = Bar(f'Running DNS lookup of possible domain permutations for {razzle.domain}…', max=len(razzle.domains)-1)
        razzle.gendom_start()
        print(f"Total permutations: {razzle.jobs_max}")
        last_completed_jobs = 0
        total_jobs = razzle.jobs_max
        last_progress_time = time.time()
        progress_interval = 60  # Seconds
        total_timeouts = 0
        first_time = True
        while not razzle.jobs.empty() or first_time:
            first_time = False
            completed_jobs = razzle.jobs_max - razzle.jobs.qsize()
            current_time = time.time()
            if no_interactive:
                if completed_jobs > last_completed_jobs and current_time - last_progress_time >= progress_interval:
                    last_progress_time = current_time
                    percentage = (completed_jobs / total_jobs) * 100
                    timeout_errors = len(razzle.get_timeout_errors())
                    percentate_timeouts = (timeout_errors / (completed_jobs - razzle.last_registered_completed_jobs)) * 100
                    razzle.last_registered_completed_jobs = completed_jobs
                    total_timeouts += timeout_errors
                    print_status(f"DNS lookup progress: {completed_jobs}/{total_jobs} ({percentage:.1f}%). Timeout errors: {timeout_errors} ({percentate_timeouts:.1f}%)")
                last_completed_jobs = completed_jobs
            else:
                bar.goto(completed_jobs)
            time.sleep(0.5)
        if no_interactive:
            percentage = 100
            percentage_timeouts = (razzle.total_timeout_errors / total_jobs) * 100
            print_status(f"DNS lookup progress: {razzle.jobs_max}/{razzle.jobs_max} ({percentage:.1f}%). Timeout errors: {total_timeouts} ({percentage_timeouts:.1f}%)")
            print_good(f"Generated DNS lookup of possible domain permutations for {razzle.domain}")
        else:
            bar.goto(bar.max)
            bar.finish()
        if debug:
            print_good(f"Generated domains dictionary: \n{razzle.domains}")

    if not no_whois:
        for razzle in razzles:
            if no_interactive:
                print_status(f"Running WHOIS queries on discovered domains for {razzle.domain}…")
                razzle.completed_domains = 0
                razzle.total_domains = len(razzle.domains)
                last_progress_time = time.time()
                progress_interval = 60  # Seconds
                def progress_callback():
                    nonlocal last_progress_time
                    current_time = time.time()
                    razzle.completed_domains += 1
                    if current_time - last_progress_time >= progress_interval:
                        percentage = (razzle.completed_domains / razzle.total_domains) * 100
                        print_status(f"WHOIS queries progress: {razzle.completed_domains}/{razzle.total_domains} ({percentage:.0f}%)")
                        last_progress_time = current_time
                razzle.whois(progress_callback)
                percentage = 100
                print_status(f"WHOIS queries progress: {razzle.total_domains}/{razzle.total_domains} ({percentage:.0f}%)")
                print_good(f"Generated WHOIS queries for {razzle.domain}")
            else:
                pBar = Bar(f'Running WHOIS queries on discovered domains for {razzle.domain}…', max=len(razzle.domains))
                razzle.whois(pBar.next)
                pBar.finish()

    print_status("Processing domain information")
    with open(out_dir + '/discovered-domains.csv', 'w') as f:
        header_written = False
        writer = csv.DictWriter(f, IOUtil.domain_entry_keys)
        counter = 0
        for razzle in razzles:
            if not header_written:
                writer.writeheader()
                header_written = True
            for d in razzle.domains:
                if (justTestLogoDetection or d['domain-name'] != razzle.domain) and 'dns-a' in d.keys() and '!ServFail' not in d['dns-a']:
                    writer.writerow(d)
                    counter += 1
    print_good(f"{counter} discovered domains written to {out_dir}/discovered-domains.csv")

    if arguments.yolo and not no_screenshot:
        if not os.path.exists(arguments.yolo):
            parser.error('Yolo weights file not found: %s' % arguments.yolo)
        from ultralytics import YOLO
        try:
            model = YOLO(arguments.yolo).to('cpu')
            print_status("Model loaded successfully")
        except Exception as e:
            print_error(f"Could not load YOLO model: {e}")
        for razzle in razzles:
            razzle.model = model

    if not no_screenshot:
        print_status("Collecting and analyzing web screenshots")

        with open(file=out_dir + "/domain_similarity.csv", mode="w") as f:
            f.write("original_domain,discovered_domain,similarity_score,logo_detection\n")

        for razzle in razzles:
            def check_domain_callback(razzle: DnsRazzle, domain_entry):
                siteA = razzle.domain
                siteB = domain_entry['domain-name']
                if 'ssim-score' not in domain_entry.keys() or not domain_entry['ssim-score']:
                    print_error(f"Could not compare {siteA} to {siteB}.")
                    return
                score = domain_entry['ssim-score']
                rounded_score = round(score, 2)
                adj = "different from"
                if rounded_score == 1.00:
                    adj = "identical to"
                elif rounded_score >= .90:
                    adj = "similar to"
                logo_present = domain_entry['logo-detection']
                print_status(f"{siteB} is {adj} {siteA} with a score of {rounded_score}. {logo_present}")
                with open(file=razzle.out_dir + "/domain_similarity.csv", mode="a") as f:
                    f.write(f"{siteA},{siteB},{rounded_score},{logo_present}\n")
            razzle.check_domains(check_domain_callback, browser=arguments.browser)
        print_good(f"Visual analysis saved to {out_dir}/domain_similarity.csv")

    if arguments.blocklist:
        print_status("Compiling blocklist")
        for razzle in razzles:
            for domain in razzle.domains:
                if 'ssim-score' in domain and domain['ssim-score'] is not None and domain['ssim-score'] >= arguments.blocklist_pct:
                    with open(out_dir + "/blocklist.csv", "a") as f:
                        for field in ['dns-a', 'dns-aaaa', 'dns-ns', 'dns-mx']:
                            if field in domain:
                                for ip in domain[field]:
                                    f.write("%s,%s" % (ip, domain['domain-name']))
        print_good(f"Blocklist saved to {out_dir}/blocklist.csv")

if __name__ == "__main__":
    main()
