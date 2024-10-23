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



from .IOUtil import print_debug, print_error
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from fake_useragent import UserAgent
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support import expected_conditions as EC

from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, WebDriverException

import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By

def is_dom_stable(driver, wait_time=0.5, retries=5):
    """
    Check if the DOM is stable by monitoring the number of elements in the DOM.
    """
    previous_dom_size = len(driver.find_elements(By.XPATH, "//*"))  # Updated to new syntax
    stable_retries = 0

    for _ in range(retries):
        time.sleep(wait_time)  # Wait for a short period
        current_dom_size = len(driver.find_elements(By.XPATH, "//*"))  # Updated to new syntax
        if current_dom_size == previous_dom_size:
            stable_retries += 1  # Increment the count if DOM size remains stable
        else:
            stable_retries = 0  # Reset if DOM size changes
        previous_dom_size = current_dom_size

        # Consider DOM stable if it remains the same over a few retries
        if stable_retries >= 3:
            return True

    return False  # If retries are exhausted and the DOM is still changing, return False

def screenshot_domain(browser, domain, out_dir):
    """
    Function to take a screenshot of the supplied domain.
    It waits for the DOM to stabilize after the first page load.
    """
    domain_name = domain  # Capture domain name within this scope
    url = "http://" + str(domain_name).strip('[]')
    driver = get_webdriver(browser)

    try:
        driver.set_page_load_timeout(15)
        driver.get(url)

        try:
            # Wait for the DOM to stabilize (number of elements to stop changing)
            WebDriverWait(driver, 15).until(lambda d: is_dom_stable(d))

            # Optionally: Ensure the page is fully loaded (if needed)
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
        except TimeoutException:
            print(f"DOM did not stabilize in time for {domain_name}, continuing...")

        # Take the screenshot after the DOM is stable
        ss_path = str(out_dir + domain_name + '.png')
        driver.get_screenshot_as_file(ss_path)

        quit_webdriver(driver)
        return True
    except WebDriverException as exception:
        print_error(f"Unable to screenshot {domain_name}. {exception.msg}")
        quit_webdriver(driver)
        return False

def get_webdriver(browser_name, retries=3, delay=5):
    ua = UserAgent()
    user_agent = ua.random
    attempt = 0

    while attempt < retries:
        attempt += 1
        try:
            if browser_name == 'chrome':
                options = webdriver.ChromeOptions()
                options.add_argument(f'--user-agent={user_agent}')
                options.add_argument("--window-size=1920,1080")
                options.add_argument("--headless")
                options.page_load_strategy = 'normal'

                try:
                    s = webdriver.chrome.service.Service(executable_path=ChromeDriverManager().install())
                    return webdriver.Chrome(service=s, options=options)
                except Exception as E:
                    print(f"Unable to install/update Chrome WebDriver: {E}")

            elif browser_name == 'firefox':
                options = webdriver.FirefoxOptions()
                options.add_argument(f'--user-agent={user_agent}')
                options.add_argument("--window-size=1920,1080")
                options.add_argument("--headless")
                options.page_load_strategy = 'normal'

                try:
                    s = webdriver.firefox.service.Service(executable_path=GeckoDriverManager().install())
                    return webdriver.Firefox(service=s, options=options)
                except Exception as E:
                    print(f"Unable to install/update Firefox WebDriver: {E}")

            else:
                print(f"Unimplemented WebDriver browser: {browser_name}")
                return None

        except WebDriverException as exception:
            print(f"WebDriverException occurred: {exception.msg}")

        if attempt < retries:
            print(f"Retrying in {delay} seconds...")
            time.sleep(delay)

    print(f"Failed to start {browser_name} WebDriver after {retries} attempts.")
    return None


def quit_webdriver(driver):
    if driver is None:
        return
    try:
        driver.quit()
    except Exception as e:
        print_error(e)
