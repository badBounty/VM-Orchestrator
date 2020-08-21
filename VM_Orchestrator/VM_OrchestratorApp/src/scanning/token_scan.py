# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import os
import re
import requests
import traceback
import urllib3
import copy
import time
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Token finder module'
MODULE_IDENTIFIER = 'token_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-token'

def send_module_status_log(scan_info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'arguments': scan_info
        })
    return

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module Token Finder starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])

    print('Module Token Finder finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module Token Finder starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    scan_target(info, info['target'])

    print('Module Token Finder finished against %s' % info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')
    return


def add_token_found_vuln(scan_info, message):
    vulnerability = Vulnerability(constants.TOKEN_SENSITIVE_INFO, scan_info, message)

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_for_scanning):
    # We scan javascript files
    javascript_files_found = utils.get_js_files(url_for_scanning)
    if javascript_files_found:
        slack.send_notification_to_channel('_ Found %s javascript files at %s _' % (str(len(javascript_files_found)), url_for_scanning), SLACK_NOTIFICATION_CHANNEL)
    for javascript in javascript_files_found:
        scan_for_tokens(scan_info, url_for_scanning, javascript)
    return

def get_response(url):
    try:
        response = requests.get(url, verify=False, timeout=3)
    except requests.exceptions.SSLError:
        slack.send_error_to_channel('Url %s raised SSL Error' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.ConnectionError:
        slack.send_error_to_channel('Url %s raised Connection Error' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.ReadTimeout:
        slack.send_error_to_channel('Url %s raised Read Timeout' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.TooManyRedirects:
        slack.send_error_to_channel('Url %s raised Too Many Redirects' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except Exception:
        error_string = traceback.format_exc()
        final_error = 'On {0}, was Found: {1}'.format(url,error_string)
        slack.send_error_to_channel(final_error, SLACK_NOTIFICATION_CHANNEL)
        return None
    return response

def scan_for_tokens(scan_info, scanned_url, javascript):
    response = get_response(javascript)
    if response is None:
        return

    # We now scan the javascript file for tokens
    tokens_found = list()

    # Generic tokens
    licence_key = re.findall('license_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'license_key', 'list': licence_key})

    api_key = re.findall('api_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'api_key', 'list': api_key})

    authorization = re.findall('authorization:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'authorization', 'list': authorization})

    access_token = re.findall('access_token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access_token', 'list': access_token})

    access_token2 = re.findall('access-token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access-token', 'list': access_token2})

    token_1 = re.findall('Token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'Token', 'list': token_1})

    token_2 = re.findall('token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'token', 'list': token_2})

    # Specific Tokens
    # ------------------------------ Algolia ------------------------------
    # Algolia uses algoliasearch for connecting inside a js, we will search the key pair
    algolia_key_pair = re.findall('algoliasearch\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'algoliasearch', 'list': algolia_key_pair})

    # ------------------------------ Asana ------------------------------
    asana_access_token = re.findall('useAccessToken\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'useAccessToken(Asana)', 'list': asana_access_token})

    # ------------------------------ AWS ------------------------------
    access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access_key_id', 'list': access_key_ids})
    secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'secret_access_key_id', 'list': secret_access_key_ids})

    # ------------------------------ Bitly ------------------------------
    bitlyTokens = re.findall('BitlyClient\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'BitlyClient', 'list': bitlyTokens})

    # ------------------------------ Branchio ------------------------------
    # Here we will get the whole client definithion, which contains key and secret_key
    branchioInfo = re.findall('branchio\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'branchio', 'list': branchioInfo})

    # ------------------------------ Dropbox ------------------------------
    # Dropbox uses a method to set access token inside the javascript code
    dropboxToken = re.findall('Dropbox\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Dropbox', 'list': dropboxToken})

    # ------------------------------ Firebase ------------------------------
    firebaseConfig = re.findall('firebaseConfig(.+?)\};', response.text)
    tokens_found.append({'keyword': 'firebaseConfig', 'list': firebaseConfig})

    # ------------------------------ Gitlab ------------------------------
    gitlabInfo = re.findall('Gitlab\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Gitlab', 'list': gitlabInfo})

    # ------------------------------ Google cloud messaging ------------------------------
    gcm_key = re.findall('gcm.Sender\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'gcm.Sender', 'list': gcm_key})

    # ------------------------------ Google maps ------------------------------
    g_maps_key = re.findall("require('@google/maps').createClient\(\{(.+?)\}\);", response.text)
    tokens_found.append({'keyword': 'google/maps', 'list': g_maps_key})

    # ------------------------------ Google autocomplete ------------------------------
    g_autocomplete_key = re.findall("googleAutoCompleteKey:Object\(\{(.+?)\}\)", response.text)
    tokens_found.append({'keyword': 'googleAutoCompleteKey', 'list': g_autocomplete_key})

    # ------------------------------ Google recaptcha ------------------------------
    g_recaptcha_key = re.findall('GoogleRecaptcha\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'GoogleRecaptcha', 'list': g_recaptcha_key})

    # ------------------------------ Hubspot ------------------------------
    hubspot_key = re.findall('Hubspot\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'Hubspot', 'list': hubspot_key})

    # ------------------------------ Instagram ------------------------------
    instagram_config = re.findall('Instagram\((.+?)\)', response.text)
    tokens_found.append({'keyword': 'Instagram', 'list': instagram_config})

    # ------------------------------ Jump cloud ------------------------------
    jumpcloud_key = re.findall('JumpCloud\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'JumpCloud', 'list': jumpcloud_key})

    # ------------------------------ Mail Chimp ------------------------------
    mailchimp_key = re.findall('Mailchimp\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'Mailchimp', 'list': mailchimp_key})

    # ------------------------------ Pagerduty ------------------------------
    pagerduty_key = re.findall('pdapiToken\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'pdapiToken(pagerduty)', 'list': pagerduty_key})

    # ------------------------------ Paypal ------------------------------
    paypal_config = re.findall('paypal.configure\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'paypal.configure', 'list': paypal_config})

    # ------------------------------ Razorpay ------------------------------
    razorpay_key = re.findall('Razorpay\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Razorpay', 'list': razorpay_key})

    # ------------------------------ SauceLabs ------------------------------
    sauceLabs_key = re.findall('SauceLabs\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'SauceLabs', 'list': sauceLabs_key})

    # ------------------------------ Sendgrid ------------------------------
    sendgrid_key = re.findall('sendgrid_api_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'sendgrid_api_key', 'list': sendgrid_key})

    # ------------------------------ Slack ------------------------------
    slack_key = re.findall('Slack\(\{(.+?)\}\)', response.text)
    tokens_found.append({'keyword': 'Slack', 'list': slack_key})

    # ------------------------------ Spotify ------------------------------
    spotify_key = re.findall('Spotify\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Spotify', 'list': spotify_key})

    # ------------------------------ Square ------------------------------
    square_key = re.findall('oauth2.accessToken = "(.+?)"', response.text)
    tokens_found.append({'keyword': 'oauth2.accessToken(square_key)', 'list': square_key})

    # ------------------------------ Travis ------------------------------
    travis_key = re.findall('travis.auth.github.post\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'travis.auth.github.post', 'list': travis_key})

    # ------------------------------ Twilio ------------------------------
    twilio_account_sid = re.findall('accountSid =(.+?);', response.text)
    tokens_found.append({'keyword': 'accountSid(twilio)', 'list': twilio_account_sid})
    twilio_auth_token = re.findall('authToken =(.+?);', response.text)
    tokens_found.append({'keyword': 'authToken(twilio)', 'list': twilio_auth_token})

    # ------------------------------ Twitter ------------------------------
    twitter_config = re.findall('Twitter\(\{(.+?)\}\)', response.text)
    tokens_found.append({'keyword': 'Twitter', 'list': twitter_config})

    # ------------------------------ bugsnag ------------------------------
    bugsnag = re.findall('bugsnagAPI:Object\(\{(.+?)\)\}', response.text)
    tokens_found.append({'keyword': 'bugsnagAPI', 'list': bugsnag})

    # We now have every checked key on tokens_found
    if any(len(token['list']) != 0 for token in tokens_found):
        extra_info = ""
        for token in tokens_found:
            if token['list']:
                for ind_token in token['list']:
                    extra_info = extra_info + token['keyword'] + ": " + ind_token + "\n"
        add_token_found_vuln(scan_info,
                             "The following tokes were found at %s: \n %s"% (javascript, extra_info))
    return
