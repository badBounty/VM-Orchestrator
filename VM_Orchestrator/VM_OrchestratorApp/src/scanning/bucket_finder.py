# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import re
import requests
import urllib3
import subprocess
import traceback
import copy
import time
from datetime import datetime

MODULE_NAME = 'S3Bucket module'
SLACK_NOTIFICATION_CHANNEL = '#vm-s3buckets'

regions = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'ap-east-1', 'ap-south-1', 'ap-northeast-3',
           'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'cn-north-1',
           'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'me-south-1',
           'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(info):
    info = copy.deepcopy(info)
    print('Module S3 Bucket Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module S3 Bucket Scan finished against %s' % info['domain'])
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module S3 Bucket Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module S3 Bucket Scan finished against %s' % info['target'])
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

def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')']):
            res.append(item)
    return res


def scan_target(scan_information, url_to_scan):
    # We first search for buckets inside the html code
    get_buckets(scan_information, url_to_scan)
    # We now scan javascript files
    javascript_files_found = utils.get_js_files(url_to_scan)
    if javascript_files_found:
        slack.send_notification_to_channel('_ Found %s javascript files at %s _' % (str(len(javascript_files_found)), url_to_scan), SLACK_NOTIFICATION_CHANNEL)
    for javascript in javascript_files_found:
        get_buckets(scan_information, javascript)
    return

def add_vulnerability_to_mongo(scanned_url, finding_name, bucket_name, description , scan_info):
    vuln_name = constants.BUCKET
    vulnerability = Vulnerability(vuln_name, scan_info, description)
    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    return


# Bucket that allows ls
def get_ls_buckets(bucket_list, scanned_url, scan_information):
    ls_allowed_buckets = []
    does_not_exist_buckets = []
    for bucket in bucket_list:
        if any(x.isupper() for x in bucket):
            continue
        try:
            subprocess.check_output('aws s3 ls s3://' + bucket, shell=True, stderr=subprocess.STDOUT)
            description = 'Bucket %s allows content listing.' \
                          % (bucket)
            add_vulnerability_to_mongo(scanned_url, 'ls', bucket, description, scan_information)
            ls_allowed_buckets.append(bucket)
        except subprocess.CalledProcessError as e:
            if 'does not exist' in e.output.decode():
                description = 'Bucket %s is being used but it does not exist' \
                              % (bucket)
                add_vulnerability_to_mongo(scanned_url, 'nf', bucket, description, scan_information)
                does_not_exist_buckets.append(bucket)
            continue


# Buckets that allow copy and remove
def get_cprm_buckets(bucket_list, scanned_url, scan_information):
    cprm_allowed_buckets = []
    for bucket in bucket_list:
        try:
            subprocess.check_output('aws s3 cp test.txt s3://' + bucket, shell=True, stderr=subprocess.DEVNULL)
            subprocess.check_output('aws s3 rm s3://' + bucket + '/test.txt', shell=True)
            description = 'Bucket %s allows copy and remove operations.' \
                          % (bucket)
            add_vulnerability_to_mongo(scanned_url, 'cprm', bucket, description, scan_information)
            cprm_allowed_buckets.append(bucket)
        except subprocess.CalledProcessError:
            print('ERROR Called proces error at bucket finder')
            continue


def get_buckets(scan_information, url_to_scan):
    response = get_response(url_to_scan)
    if response is None:
        return

    # Buckets can come in different ways
    # Way 1: http<s>://s3.amazonaws.com/bucketName
    # Way 2: http<s>://bucketName.s3.amazonaws.com
    # Way 3: //bucketName.s3.amazonaws.com
    # Way 4: https://s3-area.amazonaws.com/<bucketName>/
    # ---------Way I----------
    buckets_first_https = re.findall('"https://s3.amazonaws.com([^\"/,]+)"', response.text)
    buckets_first_https = filter_invalids(buckets_first_https)
    buckets_first_http = re.findall('"http://s3.amazonaws.com([^\"/,]+)"', response.text)
    buckets_first_http = filter_invalids(buckets_first_http)
    # ---------Way II----------
    buckets_second_https = re.findall('https://([^\"/,]+).s3.amazonaws.com', response.text)
    buckets_second_https = filter_invalids(buckets_second_https)
    buckets_second_http = re.findall('http://([^\"/,]+).s3.amazonaws.com', response.text)
    buckets_second_http = filter_invalids(buckets_second_http)
    # ---------Way III---------
    buckets_third = re.findall('\"//(.+?).s3.amazonaws.com', response.text)
    buckets_third = filter_invalids(buckets_third)
    # ---------Way IV----------
    buckets_fourth = re.findall('https://s3.amazonaws.com/(.+?)/', response.text)
    buckets_fourth = filter_invalids(buckets_fourth)
    way_iv_bis = re.findall('https://([^\"/,]+).s3.amazonaws.com/([^\"/,]+)/', response.text)
    for bucket in way_iv_bis:
        # In this case the match are tuples, not lists
        bucket = list(bucket)
        if any(x in regions for x in bucket[0]):
            buckets_fourth.append(bucket[1])
    # ---------Way IV----------
    buckets_fourth = re.findall('https://s3.amazonaws.com/(.+?)/', response.text)
    buckets_fourth = filter_invalids(buckets_fourth)

    buckets_fifth = list()
    way_v = re.findall('https://([^.\"/,]+).([^\"/,]+).amazonaws.com', response.text)
    for bucket in way_v:
        # In this case the match are tuples, not lists
        bucket = list(bucket)
        if 's3' in bucket[1]:
            buckets_fifth.append(bucket[0])

    bucket_list = buckets_first_http + buckets_second_http + buckets_first_https + buckets_second_https + buckets_third + buckets_fourth + buckets_fifth
    bucket_list = list(dict.fromkeys(bucket_list))
    for i in range(len(bucket_list)):
        bucket_list[i] = bucket_list[i].replace('/', '')

    # We now have to check the buckets
    get_ls_buckets(bucket_list, url_to_scan, scan_information)
    get_cprm_buckets(bucket_list, url_to_scan, scan_information)

