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

from .BrowserUtil import screenshot_domain
from .NetUtil import run_portscan, run_recondns, run_whois
from .VisionUtil import compare_screenshots
import queue
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from dnstwist import DomainThread, UrlParser

class DnsRazzle():
    def __init__(self, domain, out_dir, tld, dictionary, file, useragent, debug, threads, nmap, recon, driver, nameserver = '1.1.1.1'):
        self.domains = []
        self.domain = domain
        self.out_dir = out_dir
        self.tld = tld
        self.dictionary = dictionary
        self.file = file
        self.useragent = useragent
        self.threads = threads
        self.workers = []
        self.jobs = queue.Queue()
        self.jobs_max = 0
        self.debug = debug
        self.nmap = nmap
        self.recon = recon
        self.nameserver = nameserver
        self.driver = driver

    def generate_fuzzed_domains(self):
        from dnstwist import DomainFuzz
        fuzz = DomainFuzz(self.domain, self.dictionary, self.tld)
        fuzz.generate()
        # Add additional fuzzing options (2-letter additions)
        for i in range(97, 123):
            for j in range(97, 123):
                new_domain = ".".join(self.domain.split(".")[:-1]) + chr(i) + chr(j) + "." + self.domain.split(".")[-1];
                fuzz.domains.append({"fuzzer": 'addition', "domain-name": new_domain})
        if self.tld is not None:
            for entry in fuzz.domains.copy():
                for tld in self.tld:
                    new_domain = ".".join(entry["domain-name"].split(".")[:-1]) + "." + tld;
                    fuzz.domains.append({"fuzzer": 'tld-swap', "domain-name": new_domain})
            m = getattr(fuzz, "_DomainFuzz__postprocess")
            m()
        self.domains = fuzz.domains

    def whois(self, progress_callback=None):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(run_whois, domains=[domain], nameserver=self.nameserver, progress_callback=progress_callback) for domain in self.domains]
            for future in as_completed(futures):
                future.result()

    def gendom_start(self):
        url = UrlParser(self.domain)

        for i in range(len(self.domains)):
            self.jobs.put(self.domains[i])
        self.jobs_max = len(self.domains)

        for _ in range(self.threads):
            worker = DomainThread(self.jobs)
            worker.setDaemon(True)
            worker.debug = self.debug

            worker.option_extdns = True
            worker.option_geoip = False
            worker.option_ssdeep = False
            worker.option_banners = True
            worker.option_mxcheck = True

            worker.nameservers = [self.nameserver]

            worker.uri_scheme = url.scheme
            worker.uri_path = url.path
            worker.uri_query = url.query

            worker.domain_init = url.domain
            worker.start()
            self.workers.append(worker)

    def gendom_stop(self, callback=None):
        for worker in self.workers:
            if callback is not None:
                callback()
            worker.join()

    def check_domains(self, progress_callback=None):
        success = screenshot_domain(driver=self.driver, domain=self.domain, out_dir=self.out_dir + '/screenshots/originals/')
        if not success:
            print(f"Failed to capture screenshot for original domain: {self.domain}")
            return False
        with ThreadPoolExecutor(max_workers=16) as executor:
            future_to_domain = {
                executor.submit(self.check_domain, domain_entry, progress_callback): domain_entry
                for domain_entry in self.domains
                if domain_entry['domain-name'] != self.domain and 'dns-a' in domain_entry.keys() and '!ServFail' not in domain_entry['dns-a']
            }
            for future in as_completed(future_to_domain):
                domain_entry = future_to_domain[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"Error checking domain {domain_entry['domain-name']}: {exc}")
        return True

    def check_domain(self, domain_entry, progress_callback=None):
        success = screenshot_domain(driver=self.driver, domain=domain_entry['domain-name'], out_dir=self.out_dir + '/screenshots/')
        if success:
            original_png = self.out_dir + '/screenshots/originals/' + self.domain + '.png'
            if Path(original_png).is_file():
                ssim_score = compare_screenshots(imageA=original_png,
                                                 imageB=self.out_dir + '/screenshots/' + domain_entry['domain-name'] + '.png')
                domain_entry['ssim-score'] = ssim_score
                domain_entry['screenshot'] = self.out_dir + '/screenshots/' + domain_entry['domain-name'] + '.png'
            if progress_callback:
                progress_callback(self, domain_entry)
        if self.nmap:
            run_portscan(domain_entry['domain-name'], self.out_dir)
        if self.recon:
            run_recondns(domain_entry['domain-name'], self.nameserver, self.out_dir, self.threads)

    def detect_logo(self, image_path, model, conf_threshold=0.85):
        if not os.path.exists(image_path):
            print(f"Error: The image '{image_path}' does not exist.")
            return "Error in logo detection."
        results = model.predict(image_path, conf=conf_threshold, verbose=False)
        detections = results[0].boxes  # Detections in the first image
        if len(detections) > 0:
            return "Logo detected."
        else:
            return "Logo not detected."