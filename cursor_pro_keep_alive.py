import base64
import hashlib
import os
import platform
import json
import secrets
import sys
import uuid

import requests
from colorama import Fore, Style
from enum import Enum
from typing import Optional

from exit_cursor import ExitCursor
import go_cursor_help
import patch_cursor_get_machine_id
from reset_machine import MachineIDResetter
from language import language, get_translation

os.environ["PYTHONVERBOSE"] = "0"
os.environ["PYINSTALLER_VERBOSE"] = "0"

import time
import random
from cursor_auth_manager import CursorAuthManager
import os
from logger import logging
from browser_utils import BrowserManager
from get_email_code import EmailVerificationHandler
from logo import print_logo
from config import Config
from datetime import datetime

# Define EMOJI dictionary
EMOJI = {"ERROR": get_translation("error"), "WARNING": get_translation("warning"), "INFO": get_translation("info")}


class VerificationStatus(Enum):
    """Verification status enum"""

    PASSWORD_PAGE = "@name=password"
    CAPTCHA_PAGE = "@data-index=0"
    ACCOUNT_SETTINGS = "Account Settings"


class TurnstileError(Exception):
    """Turnstile verification related exception"""

    pass


def save_screenshot(tab, stage: str, timestamp: bool = True) -> None:
    """
    Save a screenshot of the page

    Args:
        tab: Browser tab object
        stage: Stage identifier for the screenshot
        timestamp: Whether to add a timestamp
    """
    try:
        # Create screenshots directory
        screenshot_dir = "screenshots"
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        # Generate filename
        if timestamp:
            filename = f"turnstile_{stage}_{int(time.time())}.png"
        else:
            filename = f"turnstile_{stage}.png"

        filepath = os.path.join(screenshot_dir, filename)

        # Save screenshot
        tab.get_screenshot(filepath)
        logging.debug(f"Screenshot saved: {filepath}")
    except Exception as e:
        logging.warning(f"Failed to save screenshot: {str(e)}")


def check_verification_success(tab) -> Optional[VerificationStatus]:
    """
    Check if verification was successful

    Returns:
        VerificationStatus: The corresponding status if successful, None if failed
    """
    for status in VerificationStatus:
        if tab.ele(status.value):
            logging.info(get_translation("verification_success", status=status.name))
            return status
    return None



def handle_first_turnstile(tab, max_retries: int = 2, retry_interval: tuple = (1, 2)) -> bool:
    """
    Handle Turnstile verification

    Args:
        tab: Browser tab object
        max_retries: Maximum number of retries
        retry_interval: Retry interval range (min, max)

    Returns:
        bool: Whether verification was successful

    Raises:
        TurnstileError: Exception during verification process
    """
    logging.info(get_translation("detecting_turnstile"))
    save_screenshot(tab, "start")

    retry_count = 0

    try:
        while retry_count < max_retries:
            retry_count += 1
            logging.debug(get_translation("retry_verification", count=retry_count))

            try:
                # Locate verification frame element
                challenge_check = (
                    tab.ele("@id=aPYp3", timeout=2)
                    .child()
                    .child()
                    .shadow_root.ele("tag:iframe")
                    .ele("tag:body")
                    .sr("tag:input")
                )

                if challenge_check:
                    logging.info(get_translation("detected_turnstile"))
                    # Random delay before clicking verification
                    time.sleep(random.uniform(1, 3))
                    challenge_check.click()
                    time.sleep(2)

                    # Save screenshot after verification
                    save_screenshot(tab, "clicked")

                    # Check verification result
                    # if check_verification_success(tab):
                    #     logging.info(get_translation("turnstile_verification_passed"))
                    #     save_screenshot(tab, "success")
                    #     return True

            except Exception as e:
                logging.debug(f"Current attempt unsuccessful: {str(e)}")

            # Check if already verified
            # if check_verification_success(tab):
            return True

            # Random delay before next attempt
            # time.sleep(random.uniform(*retry_interval))

        # Exceeded maximum retries
        logging.error(get_translation("verification_failed_max_retries", max_retries=max_retries))
        logging.error(
            "Please visit the open source project for more information: https://github.com/chengazhen/cursor-auto-free"
        )
        save_screenshot(tab, "failed")
        return False

    except Exception as e:
        error_msg = get_translation("turnstile_exception", error=str(e))
        logging.error(error_msg)
        save_screenshot(tab, "error")
        raise TurnstileError(error_msg)


def handle_turnstile(tab, max_retries: int = 2, retry_interval: tuple = (1, 2)) -> bool:
    """
    Handle Turnstile verification

    Args:
        tab: Browser tab object
        max_retries: Maximum number of retries
        retry_interval: Retry interval range (min, max)

    Returns:
        bool: Whether verification was successful

    Raises:
        TurnstileError: Exception during verification process
    """
    logging.info(get_translation("detecting_turnstile"))
    save_screenshot(tab, "start")

    retry_count = 0

    try:
        while retry_count < max_retries:
            retry_count += 1
            logging.debug(get_translation("retry_verification", count=retry_count))

            try:
                # Locate verification frame element
                challenge_check = (
                    tab.ele("@id=cf-turnstile", timeout=2)
                    .child()
                    .shadow_root.ele("tag:iframe")
                    .ele("tag:body")
                    .sr("tag:input")
                )

                if challenge_check:
                    logging.info(get_translation("detected_turnstile"))
                    # Random delay before clicking verification
                    time.sleep(random.uniform(1, 3))
                    challenge_check.click()
                    time.sleep(2)

                    # Save screenshot after verification
                    save_screenshot(tab, "clicked")

                    # Check verification result
                    if check_verification_success(tab):
                        logging.info(get_translation("turnstile_verification_passed"))
                        save_screenshot(tab, "success")
                        return True

            except Exception as e:
                logging.debug(f"Current attempt unsuccessful: {str(e)}")

            # Check if already verified
            if check_verification_success(tab):
                return True

            # Random delay before next attempt
            time.sleep(random.uniform(*retry_interval))

        # Exceeded maximum retries
        logging.error(get_translation("verification_failed_max_retries", max_retries=max_retries))
        logging.error(
            "Please visit the open source project for more information: https://github.com/chengazhen/cursor-auto-free"
        )
        save_screenshot(tab, "failed")
        return False

    except Exception as e:
        error_msg = get_translation("turnstile_exception", error=str(e))
        logging.error(error_msg)
        save_screenshot(tab, "error")
        raise TurnstileError(error_msg)


def get_cursor_session_token(tab, user_agent, max_attempts=3, retry_interval=2):
    """
    Get Cursor session token with retry mechanism
    :param tab: Browser tab
    :param max_attempts: Maximum number of attempts
    :param retry_interval: Retry interval (seconds)
    :return: Session token or None
    """

    def _generate_pkce_pair():
        code_verifier = secrets.token_urlsafe(43)
        code_challenge_digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge_digest).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    try:

        verifier, challenge = _generate_pkce_pair()
        id = uuid.uuid4()
        client_login_url = f"https://www.cursor.com/cn/loginDeepControl?challenge={challenge}&uuid={id}&mode=login"
        tab.get(client_login_url)
        tab.ele("xpath=//span[contains(text(), 'Yes, Log In')]").click()

        auth_pooll_url = f"https://api2.cursor.sh/auth/poll?uuid={id}&verifier={verifier}"
        headers = {
            "User-Agent": user_agent,
            "Accept": "*/*"
        }
        response = requests.get(auth_pooll_url, headers=headers, timeout=5)
        data = response.json()
        accessToken = data.get("accessToken", None)
        authId = data.get("authId", "")
        if len(authId.split("|")) > 1:
            userId = authId.split("|")[1]
            token = f"{userId}%3A%3A{accessToken}"
        else:
            token = accessToken
    except e:
        print(e)
        return None

    if token is not None:
        print(f"[Register] Get Account Cookie Successfully.")
    else:
        print(f"[Register] Get Account Cookie Failed.")
    return token


def update_cursor_auth(email=None, access_token=None, refresh_token=None):
    """
    Update Cursor authentication information
    """
    auth_manager = CursorAuthManager()
    return auth_manager.update_auth(email, access_token, refresh_token)


def sign_up_account(browser, tab):
    logging.info(get_translation("start_account_registration"))
    logging.info(get_translation("visiting_registration_page", url=sign_up_url))
    tab.get(sign_up_url)

    if tab.ele("@name=first_name"):
        pass
    else:
        if handle_first_turnstile(tab) == False:
            return False

    try:
        if tab.ele("@name=first_name"):
            logging.info(get_translation("filling_personal_info"))
            tab.actions.click("@name=first_name").input(first_name)
            logging.info(get_translation("input_first_name", name=first_name))
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=last_name").input(last_name)
            logging.info(get_translation("input_last_name", name=last_name))
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=email").input(account)
            logging.info(get_translation("input_email", email=account))
            time.sleep(random.uniform(1, 3))

            logging.info(get_translation("submitting_personal_info"))
            tab.actions.click("@type=submit")

    except Exception as e:
        logging.error(get_translation("registration_page_access_failed", error=str(e)))
        return False

    if handle_turnstile(tab) == False:
        return False

    try:
        if tab.ele("@name=password"):
            logging.info(get_translation("setting_password"))
            tab.ele("@name=password").input(password)
            time.sleep(random.uniform(1, 3))

            logging.info(get_translation("submitting_password"))
            tab.ele("@type=submit").click()
            logging.info(get_translation("password_setup_complete"))

    except Exception as e:
        logging.error(get_translation("password_setup_failed", error=str(e)))
        return False

    if tab.ele("This email is not available."):
        logging.error(get_translation("registration_failed_email_used"))
        return False

    if handle_turnstile(tab) == False:
        return False

    while True:
        try:
            if tab.ele("Account Settings"):
                logging.info(get_translation("registration_success"))
                break
            if tab.ele("@data-index=0"):
                logging.info(get_translation("getting_email_verification"))
                code = email_handler.get_verification_code()
                if not code:
                    logging.error(get_translation("verification_code_failure"))
                    return False

                logging.info(get_translation("verification_code_success", code=code))
                logging.info(get_translation("inputting_verification_code"))
                i = 0
                for digit in code:
                    tab.ele(f"@data-index={i}").input(digit)
                    time.sleep(random.uniform(0.1, 0.3))
                    i += 1
                logging.info(get_translation("verification_code_input_complete"))
                break
        except Exception as e:
            logging.error(get_translation("verification_code_process_error", error=str(e)))

    if handle_turnstile(tab) == False:
        return False

    wait_time = random.randint(3, 6)
    for i in range(wait_time):
        logging.info(get_translation("waiting_system_processing", seconds=wait_time-i))
        time.sleep(1)

    logging.info(get_translation("getting_account_info"))
    tab.get(settings_url)
    try:
        usage_selector = (
            "css:div.col-span-2 > div > div > div > div > "
            "div:nth-child(1) > div.flex.items-center.justify-between.gap-2 > "
            "span.font-mono.text-sm\\/\\[0\\.875rem\\]"
        )
        usage_ele = tab.ele(usage_selector)
        if usage_ele:
            usage_info = usage_ele.text
            total_usage = usage_info.split("/")[-1].strip()
            logging.info(get_translation("account_usage_limit", limit=total_usage))
            logging.info(
                "Please visit the open source project for more information: https://github.com/chengazhen/cursor-auto-free"
            )
    except Exception as e:
        logging.error(get_translation("account_usage_info_failure", error=str(e)))

    logging.info(get_translation("registration_complete"))
    account_info = get_translation("cursor_account_info", email=account, password=password)
    logging.info(account_info)
    time.sleep(5)
    return True


class EmailGenerator:
    def __init__(
        self,
        password="".join(
            random.choices(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
                k=12,
            )
        ),
    ):
        self.domain = ""
        self.names = self.load_names()
        self.default_password = password
        self.default_first_name = self.generate_random_name()
        self.default_last_name = self.generate_random_name()

    def load_names(self):
        try:
            with open("names-dataset.txt", "r") as file:
                return file.read().split()
        except FileNotFoundError:
            logging.warning(get_translation("names_file_not_found"))
            # Fallback to a small set of default names if the file is not found
            return ["John", "Jane", "Alex", "Emma", "Michael", "Olivia", "William", "Sophia", 
                    "James", "Isabella", "Robert", "Mia", "David", "Charlotte", "Joseph", "Amelia"]

    def generate_random_name(self):
        """Generate a random username"""
        return random.choice(self.names)

    def generate_email(self, length=4):
        """Generate a random email address"""
        length = random.randint(0, length)  # Generate a random int between 0 and length
        timestamp = str(int(time.time()))[-length:]  # Use the last length digits of timestamp
        return f"{self.default_first_name}{timestamp}@{self.domain}"

    def get_account_info(self):
        """Get complete account information"""
        return {
            "email": self.generate_email(),
            "password": self.default_password,
            "first_name": self.default_first_name,
            "last_name": self.default_last_name,
        }


def get_user_agent():
    """Get user_agent"""
    try:
        # Use JavaScript to get user agent
        browser_manager = BrowserManager()
        browser = browser_manager.init_browser()
        user_agent = browser.latest_tab.run_js("return navigator.userAgent")
        browser_manager.quit()
        return user_agent
    except Exception as e:
        logging.error(f"Failed to get user agent: {str(e)}")
        return None


def check_cursor_version():
    """Check cursor version"""
    pkg_path, main_path = patch_cursor_get_machine_id.get_cursor_paths()
    with open(pkg_path, "r", encoding="utf-8") as f:
        version = json.load(f)["version"]
    return patch_cursor_get_machine_id.version_check(version, min_version="0.45.0")


def reset_machine_id(greater_than_0_45):
    if greater_than_0_45:
        # Prompt to manually execute script https://github.com/chengazhen/cursor-auto-free/blob/main/patch_cursor_get_machine_id.py
        go_cursor_help.go_cursor_help()
    else:
        MachineIDResetter().reset_machine_ids()


def print_end_message():
    logging.info("\n\n\n\n\n")
    logging.info("=" * 30)
    logging.info(get_translation("all_operations_completed"))
    logging.info("\n=== Get More Information ===")
    logging.info("📺 Bilibili UP: 想回家的前端")
    logging.info("🔥 WeChat Official Account: code 未来")
    logging.info("=" * 30)
    logging.info(
        "Please visit the open source project for more information: https://github.com/chengazhen/cursor-auto-free"
    )


if __name__ == "__main__":
    print_logo()
    
    # Add language selection
    print("\n")
    language.select_language_prompt()
    
    browser_manager = None
    accounts = []

    # with open("/Users/bytedance/project/cursor-auto-free/hotmal.txt", 'r', encoding='utf-8') as f:
    #     for line in f:
    #         line = line.strip()
    #         if line and '----' in line:
    #             email, password, auth, clientId = line.split('----')
    #             accounts.append((email.strip(), password.strip(), auth.strip(), clientId.strip()))

    for i in range(1000):
        params = {
            "card": "L5295ZJ4XP34IJ7MULW5D8M4AW0HDO88BT38GUICD8AFF0O4",
            "shuliang": 1,
            "leixing": "hotmail"
        }
        resp = requests.get("https://zizhu.shanyouxiang.com/huoqu", params=params)
        account, password, refresh_token, client_id = resp.text.split('----')

        try:
            logging.info(get_translation("initializing_program"))
            ExitCursor()

            # Prompt user to select operation mode
            print(get_translation("select_operation_mode"))
            print(get_translation("reset_machine_code_only"))
            print(get_translation("complete_registration"))

            logging.info(get_translation("initializing_browser"))

            # Get user_agent
            user_agent = get_user_agent()
            if not user_agent:
                logging.error(get_translation("get_user_agent_failed"))
                user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

            # Remove "HeadlessChrome" from user_agent
            user_agent = user_agent.replace("HeadlessChrome", "Chrome")

            browser_manager = BrowserManager()
            browser = browser_manager.init_browser(user_agent)

            # Get and print browser's user-agent
            user_agent = browser.latest_tab.run_js("return navigator.userAgent")

            logging.info(
                "Please visit the open source project for more information: https://github.com/chengazhen/cursor-auto-free"
            )
            logging.info(get_translation("configuration_info"))
            login_url = "https://authenticator.cursor.sh"
            sign_up_url = "https://authenticator.cursor.sh/sign-up"
            settings_url = "https://www.cursor.com/settings"
            mail_url = "https://tempmail.plus"

            logging.info(get_translation("generating_random_account"))

            email_generator = EmailGenerator()
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name

            logging.info(get_translation("generated_email_account", email=account))

            logging.info(get_translation("initializing_email_verification"))
            email_handler = EmailVerificationHandler(account, refresh_token, client_id)

            auto_update_cursor_auth = True

            tab = browser.latest_tab

            tab.run_js("try { turnstile.reset() } catch(e) { }")

            logging.info(get_translation("starting_registration"))
            logging.info(get_translation("visiting_login_page", url=login_url))
            tab.get(login_url)

            if sign_up_account(browser, tab):
                logging.info(get_translation("getting_session_token"))
                token = get_cursor_session_token(tab, user_agent)
                if token:
                    logging.info("final token: " + token)
                    headers = {
                        "key": "A3E99D69-0F3E-4361-A81D-488CB65D8E60",
                        "token": "0048e26b2abe4d32709c31c284b1dd921f2c9b4c2c1167750964245002c381708960829",
                        "Content-Type": "application/json"
                    }
                    apikey = token
                    param = {
                        "apikey": apikey,
                        "email": account,
                        "password": password,
                        "outDate": 10000,
                    }

                    resp = requests.post("http://43.138.106.92:9000/ai/character/insertCursor", headers=headers,
                                         json=param)

                    with open('tokens.txt', 'a', encoding='utf-8') as file:
                        file.write(token + '\n')

                    logging.info(get_translation("all_operations_completed"))
                    print_end_message()
                else:
                    logging.error(get_translation("session_token_failed"))

        except Exception as e:
            logging.error(get_translation("program_error", error=str(e)))
        finally:
            if browser_manager:
                browser_manager.quit()