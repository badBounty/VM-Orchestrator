# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine, image_creator
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import json
import xmltodict
import uuid
import xml
import copy
from datetime import datetime
import subprocess
import traceback
import os
import re
import base64
from os.path import isdir, isfile, join
from PIL import Image
from io import BytesIO
from contextlib import suppress

MODULE_NAME = 'SSL/TLS module'
MODULE_IDENTIFIER = 'tls_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-ssl-tls'

all_issues = []
list_notes = []
listFoundCipherVulns = []
listFoundCertificateVulns = []

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
    print('Module SSL/TLS starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    valid_ports = ['443']
    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url

        split_url = url.split('/')
        try:
            final_url = split_url[2]
        except IndexError:
            final_url = url
        for port in valid_ports:
            scan_target(sub_info, url, final_url+':'+port)

    print('Module SSL/TLS finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')

    return


def handle_single(info):
    info = copy.deepcopy(info)
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    url = info['target']
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    valid_ports = ['443']
    split_url = url.split('/')
    try:
        final_url = split_url[2]
    except IndexError:
        final_url = url
    print('Module SSL/TLS starting against %s' % info['target'])
    for port in valid_ports:
        scan_target(info, url, final_url+':'+port)

    print('Module SSL/TLS finished against %s' % info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')
    return


def runCipherParsing(scan_info, url_with_port, data, evidence):
    cipherParsingVerboseMode = False

    # Declaro las strings de SELF-SIGNED
    self_issuer_list = "(\*|Server CA Test 1|Server CA Production 2|Server CA Production 1|nsng10406pap Intermediate CA|nldn11519pap Intermediate CA|Intermediate CA|UBS Server CA Test 3|Rohan Machado|Rohan_Machado|CROOT|SERVER|UBSIB_CA_PTE|a302-2831-4763.stm.swissbank.com)"
    # Defino headers...
    header = ["UNIQUE", "IP", "Port", "Protocol", "Hostname", "Vulnerability Name", "CVE", "Details", "Tool", "Evidence file name"]
    header_nmap = ["IP", "Hostname", "Port", "Protocol", "State", "Service", "Reason", "Version", "Script", "Evidence file name"]
    # regular expression
    re_port = "[1-9][0-9]{0,4}"
    re_protocol = "[tT][cC][pP]|[uU][dD][pP]"
    re_ip = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    re_hostname = "(?:[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]|[a-zA-Z0-9]{1,2})"
    re_domain = re_hostname + "(?:\." + re_hostname + ")*\.[a-zA-Z]{2,63}"
    # IS "TOOL"
    re_is_sslscan = "Connected to (" + re_ip + ")" + "\\n\\nTesting SSL server " + "?(" + re_ip + "|" + re_domain + ")" + "? on port " + "?(" + re_port + ")" + "?"
    re_is_testssl = "Start \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} +-->> (" + re_ip + "):(" + re_port + ") \((" + re_ip + "|" + re_domain + ")\) <<--"
    re_is_sslyze = "CHECKING HOST\(S\) AVAILABILITY"
    # fos SSH-Audit
    re_is_sshaudit = "# general\\n\(gen\) banner:.+\\n\(gen\) software:.+\\n\(gen\) compatibility:.+\\n\(gen\) compression:"
    # for Nmap
    re_is_nmap = "Nmap scan report for ?(" + re_hostname + "|" + re_domain + ")? \(?(" + re_ip + ")\)?"

    def method_version(version, ciphers):
        cipher_lines = ""
        for cipher in ciphers:
            cipher = [item.strip() for item in cipher if item]
            if cipher[1] == version:
                if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
        return cipher_lines

    def compromised_ciphers(regex, data):
        if re.findall(regex, data):
            ciphers = re.findall(regex, data)
            cipher_lines = ""
            for cipher in ciphers:
                cipher = [item.strip() for item in cipher if item]
                if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
            return cipher_lines

    def sslscan_parse(data, evidence):
        data = data.replace("\t", " ")
        is_sslscan = re.search(re_is_sslscan, data)
        ip = is_sslscan.group(1)
        if re.search(re_domain, is_sslscan.group(2)): hostname = is_sslscan.group(2)
        else:                                         hostname = None
        port = is_sslscan.group(3)
        # Method version
        re_cipher = "([-\w]+)"
        re_supported_server_cipher = ".*" + "?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + re_cipher + " +.*? +([- \w]+).*(\d+)?.*? *(bits)?"
        if re.findall(re_supported_server_cipher, data):
            ciphers = re.findall(re_supported_server_cipher, data)
            # SSL_VERSION_2_ENABLED
            v = method_version("SSLv2", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "SSL_VERSION_2_ENABLED", None, v, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # SSL_VERSION_3_ENABLED >> CVE-2014-3566
            v = method_version("SSLv3", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "SSL_VERSION_3_ENABLED", "CVE-2014-3566", v, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            if v and "CBC" in v and "SSLv3-with-CBC-ciphers-found" not in list_notes: list_notes.append("SSLv3-with-CBC-ciphers-found")
            # TLS_VERSION_1.0_ENABLED
            v = method_version("TLSv1.0", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.0_ENABLED", None, v, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # TLS_VERSION_1.1_ENABLED
            v = method_version("TLSv1.1", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.1_ENABLED", None, v, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # WEAK_ENCRYPTION_CYPHERS >> Weak key length encryption algorithms (under 128 bits)
            cipher_lines = ""
            for cipher in ciphers:
                cipher = [item.strip() for item in cipher if item]
                if int(cipher[2]) < 128:
                    if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                    else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
            if cipher_lines: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS", None, cipher_lines, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # [NOTE] Does it contain CBC ciphers?
        re_it_has_cbc = ".*(Preferred|Accepted)(.*)"
        c = compromised_ciphers(re_it_has_cbc, data)
        if c and ("-CBC" in str(c) or "CBC-" in str(c)) and "it-has-CBC-ciphers" not in list_notes: list_notes.append("it-has-CBC-ciphers")
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        sweet32_ciphers="(IDEA-CBC-SHA|IDEA-CBC-MD5|RC2-CBC-MD5|KRB5-IDEA-CBC-SHA|KRB5-IDEA-CBC-MD5|ECDHE-RSA-DES-CBC3-SHA|ECDHE-ECDSA-DES-CBC3-SHA|SRP-DSS-3DES-EDE-CBC-SHA|SRP-RSA-3DES-EDE-CBC-SHA|SRP-3DES-EDE-CBC-SHA|EDH-RSA-DES-CBC3-SHA|EDH-DSS-DES-CBC3-SHA|DH-RSA-DES-CBC3-SHA|DH-DSS-DES-CBC3-SHA|AECDH-DES-CBC3-SHA|ADH-DES-CBC3-SHA|ECDH-RSA-DES-CBC3-SHA|ECDH-ECDSA-DES-CBC3-SHA|DES-CBC3-SHA|DES-CBC3-MD5|DES-CBC3-SHA|RSA-PSK-3DES-EDE-CBC-SHA|PSK-3DES-EDE-CBC-SHA|KRB5-DES-CBC3-SHA|KRB5-DES-CBC3-MD5|ECDHE-PSK-3DES-EDE-CBC-SHA|DHE-PSK-3DES-EDE-CBC-SHA|DES-CFB-M1|EXP1024-DHE-DSS-DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|EDH-DSS-DES-CBC-SHA|DH-RSA-DES-CBC-SHA|DH-DSS-DES-CBC-SHA|ADH-DES-CBC-SHA|EXP1024-DES-CBC-SHA|DES-CBC-SHA|EXP1024-RC2-CBC-MD5|DES-CBC-MD5|DES-CBC-SHA|KRB5-DES-CBC-SHA|KRB5-DES-CBC-MD5|EXP-EDH-RSA-DES-CBC-SHA|EXP-EDH-DSS-DES-CBC-SHA|EXP-ADH-DES-CBC-SHA|EXP-DES-CBC-SHA|EXP-RC2-CBC-MD5|EXP-RC2-CBC-MD5|EXP-KRB5-RC2-CBC-SHA|EXP-KRB5-DES-CBC-SHA|EXP-KRB5-RC2-CBC-MD5|EXP-KRB5-DES-CBC-MD5|EXP-DH-DSS-DES-CBC-SHA|EXP-DH-RSA-DES-CBC-SHA)"
        ssl2_sweet32_ciphers="(RC2-CBC-MD5|EXP-RC2-CBC-MD5|IDEA-CBC-MD5|DES-CBC-MD5|DES-CBC-SHA|DES-CBC3-MD5|DES-CBC3-SHA|DES-CFB-M1)"
        re_birthday_attack = ".*?(Preferred|Accepted).*(SSLv3|TLSv1.\d).*\s(\d+) bits +.*?" + sweet32_ciphers + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        re_ssl2_birthday_attack = ".*?(Preferred|Accepted).*(SSLv2).*\s(\d+) bits +.*?" + sweet32_ciphers + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_birthday_attack, data)
        c_ssl2 = compromised_ciphers(re_ssl2_birthday_attack, data)
        details = ""
        if c:
            if c_ssl2: details = c + "\n" + c_ssl2
            else:      details = c
        else:
            if c_ssl2: details = c_ssl2
        if details: add_issues(ip, port, "TCP", hostname, "TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", details, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        anonymous_ciphers = "([-\w]*ADH[-\w]*|[-\w]*AECDH[-\w]*)"
        re_anonymous = ".*?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + anonymous_ciphers + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_anonymous, data)
        if c: add_issues(ip, port, "TCP", hostname, "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        rc4_ciphers = "([-\w]*RC4[-\w]*)"
        re_rc4 = ".*?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + rc4_ciphers + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_rc4, data)
        if c: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        exportrsa_cipher_list="(EXP1024-DES-CBC-SHA|EXP1024-RC2-CBC-MD5|EXP1024-RC4-SHA|EXP1024-RC4-MD5|EXP-EDH-RSA-DES-CBC-SHA|EXP-DH-RSA-DES-CBC-SHA|EXP-DES-CBC-SHA|EXP-RC2-CBC-MD5|EXP-RC4-MD5)"
        re_rsa_export_freak = ".*?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + exportrsa_cipher_list + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_rsa_export_freak, data)
        if c: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_CBC_MODE_VULNERABILITY >> CVE-2011-3389 >> CBC Ciphers in SSLv3 and TLSv1.0 (Beast)
        cbc_cipher_list = "(EXP-RC2-CBC-MD5|IDEA-CBC-SHA|EXP-DES-CBC-SHA|DES-CBC-SHA|DES-CBC3-SHA|EXP-DH-DSS-DES-CBC-SHA|DH-DSS-DES-CBC-SHA|DH-DSS-DES-CBC3-SHA|EXP-DH-RSA-DES-CBC-SHA|DH-RSA-DES-CBC-SHA|DH-RSA-DES-CBC3-SHA|EXP-EDH-DSS-DES-CBC-SHA|EDH-DSS-DES-CBC-SHA|EDH-DSS-DES-CBC3-SHA|EXP-EDH-RSA-DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|EDH-RSA-DES-CBC3-SHA|EXP-ADH-DES-CBC-SHA|ADH-DES-CBC-SHA|ADH-DES-CBC3-SHA|KRB5-DES-CBC-SHA|KRB5-DES-CBC3-SHA|KRB5-IDEA-CBC-SHA|KRB5-DES-CBC-MD5|KRB5-DES-CBC3-MD5|KRB5-IDEA-CBC-MD5|EXP-KRB5-DES-CBC-SHA|EXP-KRB5-RC2-CBC-SHA|EXP-KRB5-DES-CBC-MD5|EXP-KRB5-RC2-CBC-MD5|AES128-SHA|DH-DSS-AES128-SHA|DH-RSA-AES128-SHA|DHE-DSS-AES128-SHA|DHE-RSA-AES128-SHA|ADH-AES128-SHA|AES256-SHA|DH-DSS-AES256-SHA|DH-RSA-AES256-SHA|DHE-DSS-AES256-SHA|DHE-RSA-AES256-SHA|ADH-AES256-SHA|CAMELLIA128-SHA|DH-DSS-CAMELLIA128-SHA|DH-RSA-CAMELLIA128-SHA|DHE-DSS-CAMELLIA128-SHA|DHE-RSA-CAMELLIA128-SHA|ADH-CAMELLIA128-SHA|EXP1024-RC2-CBC-MD5|EXP1024-DES-CBC-SHA|EXP1024-DHE-DSS-DES-CBC-SHA|CAMELLIA256-SHA|DH-DSS-CAMELLIA256-SHA|DH-RSA-CAMELLIA256-SHA|DHE-DSS-CAMELLIA256-SHA|DHE-RSA-CAMELLIA256-SHA|ADH-CAMELLIA256-SHA|PSK-3DES-EDE-CBC-SHA|PSK-AES128-CBC-SHA|PSK-AES256-CBC-SHA|DHE-PSK-3DES-EDE-CBC-SHA|DHE-PSK-AES128-CBC-SHA|DHE-PSK-AES256-CBC-SHA|RSA-PSK-3DES-EDE-CBC-SHA|RSA-PSK-AES128-CBC-SHA|RSA-PSK-AES256-CBC-SHA|SEED-SHA|DH-DSS-SEED-SHA|DH-RSA-SEED-SHA|DHE-DSS-SEED-SHA|DHE-RSA-SEED-SHA|ADH-SEED-SHA|PSK-AES128-CBC-SHA256|PSK-AES256-CBC-SHA384|DHE-PSK-AES128-CBC-SHA256|DHE-PSK-AES256-CBC-SHA384|RSA-PSK-AES128-CBC-SHA256|RSA-PSK-AES256-CBC-SHA384|ECDH-ECDSA-DES-CBC3-SHA|ECDH-ECDSA-AES128-SHA|ECDH-ECDSA-AES256-SHA|ECDHE-ECDSA-DES-CBC3-SHA|ECDHE-ECDSA-AES128-SHA|ECDHE-ECDSA-AES256-SHA|ECDH-RSA-DES-CBC3-SHA|ECDH-RSA-AES128-SHA|ECDH-RSA-AES256-SHA|ECDHE-RSA-DES-CBC3-SHA|ECDHE-RSA-AES128-SHA|ECDHE-RSA-AES256-SHA|AECDH-DES-CBC3-SHA|AECDH-AES128-SHA|AECDH-AES256-SHA|SRP-3DES-EDE-CBC-SHA|SRP-RSA-3DES-EDE-CBC-SHA|SRP-DSS-3DES-EDE-CBC-SHA|SRP-AES-128-CBC-SHA|SRP-RSA-AES-128-CBC-SHA|SRP-DSS-AES-128-CBC-SHA|SRP-AES-256-CBC-SHA|SRP-RSA-AES-256-CBC-SHA|SRP-DSS-AES-256-CBC-SHA|ECDHE-PSK-3DES-EDE-CBC-SHA|ECDHE-PSK-AES128-CBC-SHA|ECDHE-PSK-AES256-CBC-SHA|ECDHE-PSK-AES128-CBC-SHA256|ECDHE-PSK-AES256-CBC-SHA384|PSK-CAMELLIA128-SHA256|PSK-CAMELLIA256-SHA384|DHE-PSK-CAMELLIA128-SHA256|DHE-PSK-CAMELLIA256-SHA384|RSA-PSK-CAMELLIA128-SHA256|RSA-PSK-CAMELLIA256-SHA384|ECDHE-PSK-CAMELLIA128-SHA256|ECDHE-PSK-CAMELLIA256-SHA384)"
        re_weak_cbc_beast = ".*?(Preferred|Accepted).*(SSLv3|TLSv1.0).*\s(\d+) bits +.*?" + cbc_cipher_list + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_weak_cbc_beast, data)
        if c: add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # EDH_CIPHERS_FOUND
        EDHciphers = "([-\w]*EDH[-\w]*)"
        re_edh_ciphers = ".*?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + EDHciphers + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_edh_ciphers, data)
        if c: add_issues(ip, port, "TCP", hostname, "EDH_CIPHERS_DETECTED", "", c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> Incorrect TLS padding may be accepted when terminating TLS 1.1 and TLS 1.2 CBC cipher connections
        re_tls_poodle = ".*?(Preferred|Accepted).*(TLSv1.1|TLSv1.2).*\s(\d+) bits +.*?" + cbc_cipher_list + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        c = compromised_ciphers(re_tls_poodle, data)
        if c: add_issues(ip, port, "TCP", hostname, "TLS_POODLE_VULNERABILITY", "CVE-2014-8730", c, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM >> CVE-2015-4000 >> DHE_EXPORT Ciphers in TLS from 512 to 1024 bit keys
        exportdh_cipher_list = "(EXP1024-DHE-DSS-DES-CBC-SHA|EXP1024-DHE-DSS-RC4-SHA|EXP-EDH-RSA-DES-CBC-SHA|EXP-EDH-DSS-DES-CBC-SHA)"
        re_dhe_bit = ".*?(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*\s(\d+) bits +.*?" + exportdh_cipher_list + " +.*? +([- \w]+).*?(\d+)?.*? *(bits)?"
        if re.findall(re_dhe_bit, data):
            ciphers = re.findall(re_dhe_bit, data)
            cipher_lines = ""
            for cipher in ciphers:
                cipher = [item.strip() for item in cipher if item]
                if len(cipher) > 5:
                    if int(cipher[5]) <= 1024:
                        if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                        else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
            if cipher_lines: add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", cipher_lines, "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # EXPIRED_SSL_CERTIFICATE >> It is compared with the current date
        re_cert_datetime = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( ?[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3]|[0-9]):([0-5][0-9]):([0-5][0-9]) (\d{4})"
        re_cert_datetime_expiration = "Not valid after: *.*?" + re_cert_datetime + " GMT.*?"
        if re.search(re_cert_datetime_expiration, data):
            dformat = "%b %d %H %M %S %Y"
            cert_dexp = re.search(re_cert_datetime_expiration, data)
            ###
            dnow = datetime.now()
            dexp = datetime.strptime( " ".join(cert_dexp.groups()) , dformat)
            if dexp < dnow: add_issues(ip, port, "TCP", hostname, "EXPIRED_SSL_CERTIFICATE", None, "Not valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months
            re_cert_datetime_since = "Not valid before: *.*?" + re_cert_datetime + " GMT.*?"
            if re.search(re_cert_datetime_since, data):
                cert_dsince = re.search(re_cert_datetime_since, data)
                dsince = datetime.strptime( " ".join(cert_dsince.groups()) , dformat)
                # find better way to calculate difference
                seconds_39_weeks = (365.25/12)*(24*60*60)*39
                if (dexp - dsince).total_seconds() > seconds_39_weeks:
                    add_issues(ip, port, "TCP", hostname, "SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, "Not valid before: " + cert_dsince.group(1) + " " + cert_dsince.group(2) + " " + ":".join(cert_dsince.groups()[2:5]) + " " + cert_dsince.group(6) + "\nNot valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_RENEGOTIATION_VULNERABILITY >> CVE-2009-3555
        re_renegotiation = ".*?(Insecure).*? session renegotiation supported"
        if re.search(re_renegotiation, data): add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", "Insecure session renegotiation supported", "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_compression = "Compression .*?(enabled).*? (CRIME)"
        if re.search(re_compression, data): add_issues(ip, port, "TCP", hostname, "SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "Compression enabled (CRIME)", "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION >> CVE-2004-2761
        re_md5_rsa = "Signature Algorithm: .*?(md5WithRSAEncryption).*?"
        if re.search(re_md5_rsa, data):
            md5_rsa = re.search(re_md5_rsa, data)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", "Signature Algorithm: " + md5_rsa.group(1), "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION
        re_sha1_rsa = "Signature Algorithm: .*?(sha1WithRSAEncryption).*?"
        if re.search(re_sha1_rsa, data):
            sha1_rsa = re.search(re_sha1_rsa, data)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, "Signature Algorithm: " + sha1_rsa.group(1), "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SERVER_PUBLIC_KEY_TOO_SMALL >> RSA Key Strength: Menor a 2048
        re_rsa_key = "RSA Key Strength: +.*?\s(\d+).*?"
        if re.search(re_rsa_key, data):
            rsa_key = re.search(re_rsa_key, data)
            if int(rsa_key.group(1)) < 2048:
                add_issues(ip, port, "TCP", hostname, "SERVER_PUBLIC_KEY_TOO_SMALL", None, "RSA Key Strength: " + rsa_key.group(1), "SSLScan", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)

    def testssl_parse(data, evidence):
        data = data.replace("\t", " ")
        is_testssl = re.search(re_is_testssl, data)
        ip = is_testssl.group(1)
        port = is_testssl.group(2)
        if re.search(re_domain, is_testssl.group(3)): hostname = is_testssl.group(3)
        else:                                         hostname = None
        # SSL_VERSION_2_ENABLED
        re_testssl_sslv2 = "SSLv2 .*?(supported but couldn't detect a cipher and vulnerable to CVE-2015-3197|offered \(NOT ok\), also VULNERABLE to DROWN attack|offered \(NOT ok\)|CVE-2015-3197: supported but couldn't detect a cipher).*?([-\w ]+)?"
        if re.search(re_testssl_sslv2, data):
            testssl_sslv2 = re.search(re_testssl_sslv2, data)
            if testssl_sslv2.group(2): details = "SSLv2 " + testssl_sslv2.group(1) + testssl_sslv2.group(1)
            else:                      details = "SSLv2 " + testssl_sslv2.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_VERSION_2_ENABLED", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            if "also VULNERABLE to DROWN attack" in details:
                add_issues(ip, port, "TCP", hostname, "SSL2_DROWN_ATACK", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_VERSION_3_ENABLED >> CVE-2014-3566
        re_testssl_sslv3 = "SSLv3 .*?(offered \(NOT ok\)|server responded with higher version number \(TLSv1[.]+\) than requested by client \(NOT ok\)|server responded with version number [.]+ \(NOT ok\)|strange, server [.]+|supported but couldn't detect a cipher \(may need debugging\)).*?"
        if re.search(re_testssl_sslv3, data):
            testssl_sslv3 = re.search(re_testssl_sslv3, data)
            details = "SSLv3 " + testssl_sslv3.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_VERSION_3_ENABLED", "CVE-2014-3566", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_VERSION_1.0_ENABLED
        re_testssl_tls10 = "TLS 1 .*(offered.*(?: \(deprecated\))?|supported but couldn't detect a cipher \(may need debugging\))"
        if re.search(re_testssl_tls10, data):
            testssl_tls10 = re.search(re_testssl_tls10, data)
            details = "TLS 1.0 " + testssl_tls10.group(1).replace("\x1b[m","")
            add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.0_ENABLED", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        re_testssl_anonymous = "Anonymous NULL Ciphers (no authentication) .*?(offered \(NOT ok\)).*?"
        if re.search(re_testssl_anonymous, data):
            testssl_anonymous = re.search(re_testssl_anonymous, data)
            details = "Anonymous NULL Ciphers (no authentication) " + testssl_anonymous.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION >> CVE-2004-2761
        re_testssl_md5_rsa = "(Signature Algorithm ) .*?(MD5)"
        if re.search(re_testssl_md5_rsa, data):
            testssl_md5_rsa = re.search(re_testssl_md5_rsa, data)
            details = ""
            for i in range(testssl_md5_rsa.lastindex):
                index = i + 1
                if testssl_md5_rsa.group(index):
                    if not details: details = testssl_md5_rsa.group(index)
                    else:           details = details + testssl_md5_rsa.group(index)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION
        re_testssl_sha1_rsa = "(Signature Algorithm ) .*?(SHA1 with RSA|ECDSA with SHA1|DSA with SHA1|RSASSA-PSS with SHA1).*?( -- besides: users will receive a )?.*?(strong browser WARNING)?"
        if re.search(re_testssl_sha1_rsa, data):
            testssl_sha1_rsa = re.search(re_testssl_sha1_rsa, data)
            details = ""
            for i in range(testssl_sha1_rsa.lastindex):
                index = i + 1
                if testssl_sha1_rsa.group(index):
                    if not details: details = testssl_sha1_rsa.group(index)
                    else:           details = details + testssl_sha1_rsa.group(index)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SERVER_PUBLIC_KEY_TOO_SMALL >> EC Keys Strength: Menor a 224 >> RSA, DSA, DH Keys Strength: Menor a 2048
        re_testssl_key = "Server key size .*?([\w]+).*\s([\d]+).*? bits"
        if re.search(re_testssl_key, data):
            testssl_key = re.search(re_testssl_key, data)
            details = ""
            if testssl_key.group(1) == "EC" or testssl_key.group(1) == "ECDSA":
                if int(testssl_key.group(2)) < 224:  details = "Server key size " + testssl_key.group(1) + " " + testssl_key.group(2) + " bits"
            else:
                if int(testssl_key.group(2)) < 2048: details = "Server key size " + testssl_key.group(1) + " " + testssl_key.group(2) + " bits"
            if len(details) > 0:
                add_issues(ip, port, "TCP", hostname, "SERVER_PUBLIC_KEY_TOO_SMALL", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SELF_SIGNED_SSL_CERTIFICATES >> If issuer is same as hostname we scanned, is * or is one of those listed in self_issuer_list, flag as self-signed
        '''re_issuer = "Issuer .*?(?:.*?(self-signed \(NOT ok\))|.*?(.+).*? \(.*?(.+).*? from .*?(\w+).*?\))"
        if re.search(re_issuer, data):
            ciss = re.search(re_issuer, data)
            details = ""
            if ciss.group(1): details = "Issuer " + ciss.group(1)
            else:
                issuer_found = ciss.group(2).replace("\x1b[m","")
                if re.search(self_issuer_list, issuer_found): details = "Issuer " + issuer_found
            if len(details) > 0: add_issues(ip, port, "TCP", hostname, "SELF_SIGNED_SSL_CERTIFICATES", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)'''
        # EXPIRED_SSL_CERTIFICATE >> It is compared with the current date
        re_datetime = "([\d]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])"
        re_cert_datetime = "Certificate (?:Validity \(UTC\)|Expiration) .*(?:[ <>=()\w\d]+|expired!?).* \((?:UTC: )?" + re_datetime + " --> " + re_datetime + "(?: -[\d]{4})?\)(?:\\n +)?.*([>= \d\w]+)?"
        if re.search(re_cert_datetime, data):
            cert_datetime = re.search(re_cert_datetime, data)
            dformat = "%Y %m %d %H %M"
            nowdate = datetime.now()
            startdate = datetime.strptime(" ".join(cert_datetime.groups()[0:5]), dformat)
            enddate = datetime.strptime(" ".join(cert_datetime.groups()[5:10]) , dformat)
            if enddate < nowdate:
                details = "Certificate Validity (UTC) expired (" + "-".join(cert_datetime.groups()[0:3]) + " " + ":".join(cert_datetime.groups()[3:5]) + " --> " + "-".join(cert_datetime.groups()[5:8]) + " " + ":".join(cert_datetime.groups()[8:10]) + ")"
                add_issues(ip, port, "TCP", hostname, "EXPIRED_SSL_CERTIFICATE", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months >> find better way to calculate difference
            seconds_39_weeks = (365.25/12)*(24*60*60)*39
            if (enddate - startdate).total_seconds() > seconds_39_weeks:
                details = "Certificate Validity (UTC) (" + "-".join(cert_datetime.groups()[0:3]) + " " + ":".join(cert_datetime.groups()[3:5]) + " --> " + "-".join(cert_datetime.groups()[5:8]) + " " + ":".join(cert_datetime.groups()[8:10]) + ")"
                if cert_datetime.group(11): details = details + "\n" + cert_datetime.group(11)
                add_issues(ip, port, "TCP", hostname, "SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_ROBOT_ATTACK
        re_robot = "ROBOT .*?VULNERABLE \(NOT ok\).*?([-\w ]+)?"
        if re.search(re_robot, data):
            robot = re.search(re_robot, data)
            if robot.group(1): details = "ROBOT VULNERABLE (NOT ok)" + robot.group(1)
            else:              details = "ROBOT VULNERABLE (NOT ok)"
            add_issues(ip, port, "TCP", hostname, "TLS_ROBOT_ATTACK", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_RENEGOTIATION_VULNERABILITY >> CVE-2009-3555
        re_renegotiation = "Secure Renegotiation .*\((RFC 5746|CVE-2009-3555)\) .*(Not supported \/ )?VULNERABLE \(NOT ok\)"
        re_client_renegotiation = "Secure Client-Initiated Renegotiation +(?:\\x1b\[(?:\d)?(?:;3\d)?m)*VULNERABLE \(NOT ok\)(?:\\x1b\[(?:\d)?(?:;3\d)?m)*, ([\w ]+)"
        details = ""
        if re.search(re_renegotiation, data):
            renegotiation = re.search(re_renegotiation, data)
            if renegotiation.group(2): details = "Secure Renegotiation (" + renegotiation.group(1) + ") " + renegotiation.group(2) + " VULNERABLE (NOT ok)"
            else:                      details = "Secure Renegotiation (" + renegotiation.group(1) + ") VULNERABLE (NOT ok)"
        ''' NO ANALIZAMOS EL CLIENT-INITIATED RENEGOTIATION !!!!
        if re.search(re_client_renegotiation, data):
            client_renegotiation = re.search(re_client_renegotiation, data)
            if not details:
                details = "Secure Client-Initiated Renegotiation VULNERABLE (NOT ok), " + client_renegotiation.group(1)
            else:
                details = details + "\nSecure Client-Initiated Renegotiation VULNERABLE (NOT ok), " + client_renegotiation.group(1) '''
        if details: add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_testssl_compression = "CRIME, TLS .*\(CVE-2012-4929\) .*(VULNERABLE [ :()\w]+)"
        if re.search(re_testssl_compression, data):
            testssl_compression = re.search(re_testssl_compression, data)
            add_issues(ip, port, "TCP", hostname, "SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "CRIME, TLS (CVE-2012-4929) " + testssl_compression.group(1), "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> TestSSL does not detect Poodle in TLS, only in SSL
        ''' EMPTY '''
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        re_testssl_sweet32 = "SWEET32.*? \(CVE-2016-2183, CVE-2016-6329\) +.*?VULNERABLE(.*)"
        if re.search(re_testssl_sweet32, data):
            testssl_sweet32 = re.search(re_testssl_sweet32, data)
            details = "SWEET32 (CVE-2016-2183, CVE-2016-6329) VULNERABLE" + testssl_sweet32.group(1)
            add_issues(ip, port, "TCP", hostname, "TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        re_testssl_freak = "FREAK.*? \(CVE-2015-0204\) +.*?VULNERABLE \(NOT ok\).*?([\w]+)"
        if re.search(re_testssl_freak, data):
            testssl_freak = re.search(re_testssl_freak, data)
            details = "FREAK (CVE-2015-0204) VULNERABLE (NOT ok), " + testssl_freak.group(1)
            add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM >> CVE-2015-4000 >> DHE_EXPORT Ciphers in TLS from 512 to 1024 bit keys
        re_testssl_logjam = "LOGJAM (.*)?(VULNERABLE \(NOT ok\))?(.* uses DH EXPORT ciphers)?(?:\\n +)?.*?(VULNERABLE \(NOT ok\)):(.*)"
        if re.search(re_testssl_logjam, data):
            testssl_logjam = re.search(re_testssl_logjam, data)
            details = "LOGJAM "
            for i in range(testssl_logjam.lastindex):
                index = i + 1
                if testssl_logjam.group(index):
                    if testssl_logjam.group(index) == "VULNERABLE (NOT ok)":
                        details = details + "\n" + testssl_logjam.group(index) + ":"
                    else:
                        details = details + testssl_logjam.group(index)
            add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_CBC_MODE_VULNERABILITY >> CVE-2011-3389 >> CBC Ciphers in SSLv3 and TLSv1.0 (Beast)
        re_testssl_beast = "BEAST.*? \(CVE-2011-3389\) +([\w]+): .*?([- \w]+)(?:\\n +)?([- \w]+)?.*?(?:\\n +)?([\w]+)?(?:: )?.*?([- \w]+)?(?:\\n +)?([- \w]+)?.*?(?:\\n +)?.*?(VULNERABLE)?.*?([-:.\(\) \w]+)?"
        if re.search(re_testssl_beast, data):
            testssl_beast = re.search(re_testssl_beast, data)
            details = ""
            for i in range(testssl_beast.lastindex):
                index = i + 1
                if testssl_beast.group(index):
                    details = details + " " + testssl_beast.group(index)
            details = details.replace(" -", "-").replace("- ", "-").replace("VULNERABLE--", "\nVULNERABLE -- ")
            add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        re_testssl_rc4 = "RC4.*? \(CVE-2013-2566, CVE-2015-2808\) +.*?VULNERABLE \(NOT ok\): .*?([- \w]+)"
        if re.search(re_testssl_rc4, data):
            testssl_rc4 = re.search(re_testssl_rc4, data)
            details = "RC4 (CVE-2013-2566, CVE-2015-2808) VULNERABLE (NOT ok): " + testssl_rc4.group(1)
            add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # PERFECT_FORWARD_SECRECY_DISABLED
        if "No ciphers supporting Forward Secrecy (FS) offered" in data:
            details = "No ciphers supporting Forward Secrecy (FS) offered"
            add_issues(ip, port, "TCP", hostname, "PERFECT_FORWARD_SECRECY_DISABLED", None, details, "TestSSL", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)

    def sslyze_parse(data, evidence):
        is_sslyze = re.search(re_is_sslyze, data)
        tmpData = (''.join(data)).split("\n")
        sslyzeIPandPort = (str(tmpData[3])[:str(tmpData[3]).find("=>")]).replace(" ", "").replace("\t", "")
        ip = sslyzeIPandPort[:sslyzeIPandPort.find(":")]
        port = sslyzeIPandPort[sslyzeIPandPort.find(":")+1:]
        if re.search(re_ip, ip): hostname = None
        else:                    hostname = ip
        if ip == hostname: # Si en lugar de una IP tenemos un Hostname, la IP estará luego del "=>"
            tmpIP = (str(tmpData[3])[str(tmpData[3]).find("=>")+3:]).replace(" ", "").replace("\n", "")
            if re.search(re_ip, tmpIP): ip = tmpIP # cambio www.example.com por su IP
        # SSLYZE ROBOT
        for i in range(len(tmpData)):
            if " * ROBOT Attack:" in tmpData[i]:
                if "VULNERABLE" in tmpData[i+1]:
                    details = str(tmpData[i+1])[str(tmpData[i+1]).find("VULNERABLE"):].replace("\n", "")
                    add_issues(ip, port, "TCP", hostname, "TLS_ROBOT_ATTACK", None, details, "SSLYZE", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSLYZE RENEGOTIATION
        for i in range(len(tmpData)):
            if " * Session Renegotiation:" in tmpData[i]:
                if "Secure Renegotiation:" in tmpData[i+2] and "VULNERABLE" in tmpData[i+2]:
                    details = str(tmpData[i+2])[str(tmpData[i+2]).find("VULNERABLE"):].replace("\n", "")
                    add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", None, details, "SSLYZE", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_VERSION_2_ENABLED
        details = ""
        for i in range(len(tmpData)):
            with suppress(Exception):
                if "* SSL 2.0 Cipher suites:" in tmpData[i] and "The server accepted" in tmpData[i+3]:
                    k = -1
                    while k != len(tmpData):
                        k += 1 # Empieza en cero...
                        if str(tmpData[i+4+k]) == "\n" or str(tmpData[i+4+k]) == "": break # Si ya no hay mas ciphers, salgo...
                        details += str(tmpData[i+4+k]).strip() + "\n"
                    add_issues(ip, port, "TCP", hostname, "SSL_VERSION_2_ENABLED", None, details, "SSLYZE", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_VERSION_3_ENABLED
        details = ""
        for i in range(len(tmpData)):
            with suppress(Exception):
                if "* SSL 3.0 Cipher suites:" in tmpData[i] and "The server accepted" in tmpData[i+3]:
                    k = -1
                    while k != len(tmpData):
                        k += 1 # Empieza en cero...
                        if str(tmpData[i+4+k]) == "\n" or str(tmpData[i+4+k]) == "": break # Si ya no hay mas ciphers, salgo...
                        details += str(tmpData[i+4+k]).strip() + "\n"
                    add_issues(ip, port, "TCP", hostname, "SSL_VERSION_3_ENABLED", None, details, "SSLYZE", evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        import time; time.sleep(10)
                 
    def add_issues(ip, port, protocol, hostname, vulnerability, cve, details, tool, evidence, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns):
        if cve is None: cve = "" # Para evitar un error en ip+":"+port+":"+vulnerability+":"+cve (concatenate "str"+None)
        details = "> " + details.replace("\n", "\n> ")
        isCipherVuln = True
        isCertificateVuln = True
        # CERTIFICATE vulnerabilities:
        if vulnerability == "EXPIRED_SSL_CERTIFICATE": message = "The certificate is expired:\n"+details
        elif vulnerability == "SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE": message = "The certificate date is invalid:\n"+details
        elif vulnerability == "SELF_SIGNED_SSL_CERTIFICATES": message = "The certificate is self-signed:\n"+details
        elif vulnerability == "SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY": message = "This server is vulnerable to a CRIME attack (SSL/TLS compression is active):\n" + details
        elif vulnerability == "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION": message = "The certificate is using MD5 signature which is considered insecure:\n" + details
        elif vulnerability == "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION": message = "The certificate is using MD5 signature which is considered insecure:\n" + details
        elif vulnerability == "SERVER_PUBLIC_KEY_TOO_SMALL": message = "The server certificate is using a small RSA Key (less than 2048-bit length):\n" + details
        elif vulnerability == "TLS_RENEGOTIATION_VULNERABILITY": message = "The server is vulnerable to the TLS Renegotiation vulneraiblity:\n" + details
        elif vulnerability == "TLS_ROBOT_ATTACK": message = "A weakness in the RSA encryption which could allow an attacker to retrieve the private key in a relatively short amount of time was found (ROBOT ATTACK):\n" + details
        else: isCertificateVuln = False
        # CIPHER vulnerabilities:
        if tool.upper() in ["SSLSCAN", "SSLYZE"]:
            if vulnerability == "SSL_VERSION_2_ENABLED": message = "The following SSLv2 cipher suites were found:\n" + details
            elif vulnerability == "SSL_VERSION_3_ENABLED": message = "The following SSLv3 cipher suites were found:\n" + details
            elif vulnerability == "TLS_VERSION_1.0_ENABLED": message = "The following TLSv1.0 cipher suites were found:\n" + details
            elif vulnerability == "TLS_VERSION_1.1_ENABLED": message = "The following TLSv1.1 cipher suites were found:\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS": message = "The following ciphers have keys smaller than 128-bit:\n" + details 
            elif vulnerability == "TLS_BIRTHDAY_ATTACK_POSSIBLE": message = "The following ciphers are vulnerable to Birthday attacks:\n" + details
            elif vulnerability == "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED": message = "The following ciphers are vulnerable to \"Server anonymous authentication\" (ADH and AECDH ciphers):\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK": message = "The following ciphers are vulnerable to the FREAK vulnerability:\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS": message = "The following ciphers are vulnerable (RC4):\n" + details
            elif vulnerability == "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY": message = "The following SSLv3/TLSv1.0 ciphers are vulnerable to the BEAST vulnerability:\n" + details
            elif vulnerability == "EDH_CIPHERS_DETECTED": message = "The following EDH ciphers were found:\n" + details
            elif vulnerability == "TLS_POODLE_VULNERABILITY": message = "The following TLSv1.1/TLSv1.2 ciphers could lead to TLS Poodle vulnerabilities (ZombiePOODLE/GoldenPOODLE):\n" + details
            elif vulnerability == "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM": message = "The following ciphers are vulnerable to LOGJAM (DHE_EXPORT ciphers with 512 to 1024 bit keys):\n" + details
            elif vulnerability == "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED": message = "The following anonymous cipher suites were found (allowing anonymous authentication):\n" + details
            else: isCipherVuln = False
        else:
            if vulnerability == "SSL_VERSION_2_ENABLED": message = "The target has SSLv2 enabled:\n" + details
            elif vulnerability == "SSL_VERSION_3_ENABLED": message = "The target has SSLv3 enabled:\n" + details
            elif vulnerability == "TLS_VERSION_1.0_ENABLED": message = "The target has TLSv1.0 enabled:\n" + details
            elif vulnerability == "TLS_VERSION_1.1_ENABLED": message = "The target has TLSv1.1 enabled:\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS": message = "The target has weak ciphers enabled (with keys smaller than 128-bit):\n" + details
            elif vulnerability == "TLS_BIRTHDAY_ATTACK_POSSIBLE": message = "The target is vulnerable to Birthday attacks:\n" + details
            elif vulnerability == "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED": message = "The target is vulnerable to the \"Server anonymous authentication\" vulnerability (due to ADH and AECDH ciphers):\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK": message = "The following ciphers are vulnerable to the FREAK vulnerability:\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS": message = "The target has RC4 vulnerable ciphers:\n" + details
            elif vulnerability == "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY": message = "The target is vulnerable to the BEAST vulnerability:\n" + details
            elif vulnerability == "EDH_CIPHERS_DETECTED": message = "The target has vulnerable EDH ciphers:\n" + details
            elif vulnerability == "TLS_POODLE_VULNERABILITY": message = "The target is vulnerable to TLS Poodle vulnerabilities (ZombiePOODLE/GoldenPOODLE):\n" + details
            elif vulnerability == "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM": message = "The target is vulnerable to LOGJAM (DHE_EXPORT ciphers with 512 to 1024 bit keys):\n" + details
            elif vulnerability == "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED": message = "The target is vulnerable to the Anonymous Authentication vulnerability: \n" + details
            elif vulnerability == "PERFECT_FORWARD_SECRECY_DISABLED": message = "The target does not present Perfect Forward Secrecy:\n" + details
            elif vulnerability == "SSL2_DROWN_ATACK": message = "The target is vulnerable to SSLv3 DROWN Attack:\n" + details
            else: isCipherVuln = False
        # Just in case that it's none of the reported ones (it should never happen)
        if not isCipherVuln and not isCertificateVuln:
            print("Warning, coding error, vulnerability \"" + str(vulnerability) + "\" not correctly assigned.")
            return
        # If it is a CERTIFICATE vuln or CIPHER vuln, it will be added into its corresponding list...
        if isCertificateVuln: listFoundCertificateVulns.append([scan_info, url_with_port, message, vulnerability, tool])
        if isCipherVuln:      listFoundCipherVulns.append([scan_info, url_with_port, message, vulnerability, tool])

    sslscan_positions = []
    for i in re.finditer(re_is_sslscan, data): sslscan_positions.append(i.start())

    testssl_positions = []
    for i in re.finditer(re_is_testssl, data):
        testssl_positions.append(i.start())

    sslyze_positions = []
    for i in re.finditer(re_is_sslyze, data): sslyze_positions.append(i.start())
    
    limits = sslscan_positions + testssl_positions + sslyze_positions
    limits.sort()

    msj_other = False
    for i in range(len(limits)):
        if i == len(limits)-1:
            lstart = limits[i]
            lend = len(data)
        else:
            lstart = limits[i]
            lend = limits[i+1]

        if re.search(re_is_sslscan, data[lstart:lend]):   sslscan_parse(data[lstart:lend], evidence)
        elif re.search(re_is_testssl, data[lstart:lend]): testssl_parse(data[lstart:lend], evidence)
        elif re.search(re_is_sslyze, data[lstart:lend]):  sslyze_parse(data[lstart:lend], evidence)


def cleanup(path):
    with suppress(FileNotFoundError):
        os.remove(path)


def add_vulnerability(scan_info, message, isCipherVuln=False, isCertVuln=False, img_str_list=None, outputFiles=None):
    if isCipherVuln: vulnerability = Vulnerability(constants.SSL_TLS_CIPHERS, scan_info, message)
    elif isCertVuln: vulnerability = Vulnerability(constants.SSL_TLS_CERTIFICATE, scan_info, message)
    else: return # If it's neither declared as CIPHER VULN nor as CERT VULN leave function...
    if img_str_list:
        for i in range(len(img_str_list)): # img_str_list tells which tools had results... [True, False, False] means only SSLSCAN brought active vulnerabilities
            with suppress(Exception):
                if img_str_list[i] == False: continue # if no issues were found with a tool, continue...
                img_str = image_creator.create_image_from_file(outputFiles[i])
                vulnerability.add_image_string(img_str)
                ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
                output_dir = ROOT_DIR+'/tools_output/' + str(uuid.uuid4().hex) + '.png'
                im = Image.open(BytesIO(base64.b64decode(img_str)))
                im.save(output_dir, 'PNG')
                if i == 0: vulnerability.add_attachment(output_dir, 'SSLSCAN-result.png')
                if i == 1: vulnerability.add_attachment(output_dir, 'TestSSL-result.png')
                if i == 2: vulnerability.add_attachment(output_dir, 'SSLYZE-result.png')


    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    
    # Borro los archivos temporales...
    for i in range(len(outputFiles)):
        with suppress(Exception): os.remove(outputFiles[i])
    with suppress(Exception): os.remove('SSLSCAN-result.png')
    with suppress(Exception): os.remove('TestSSL-result.png')
    with suppress(Exception): os.remove('SSLYZE-result.png')


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(scan_info, url, url_with_port):
    global all_issues; all_issues = []
    global list_notes; list_notes = []
    global listFoundCipherVulns; listFoundCipherVulns = []
    global listFoundCertificateVulns; listFoundCertificateVulns = []

    outputFiles = ["", "", ""]

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'

    for i in range(3):
        random_filename = uuid.uuid4().hex
        OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + random_filename + '.txt'
        #cleanup(OUTPUT_FULL_NAME)

        # We first run the subprocess that creates the xml output file
        if i == 0: sp = subprocess.run(['sslscan', '--no-failed', '--no-colour', url_with_port], capture_output=True, timeout=500)
        if i == 1: sp = subprocess.run([TOOL_DIR, '--fast', '--color', '0', '--warnings=off', url_with_port], capture_output=True, timeout=500)
        if i == 2: sp = subprocess.run(['sslyze', '--reneg', '--robot', '--sslv2', '--sslv3', str(url_with_port)], capture_output=True, timeout=300)
        
        data = sp.stdout.decode()

        #with open(ROOT_DIR + "/tools_output/" + tool + ".txt", "r") as f: data = f.read()

        # Despues borrar esta parte de guardado de archivo (no usada)...
        #with open(ROOT_DIR + "/tools_output/" + tool + ".txt", "w") as f: f.write(data)
        with open(OUTPUT_FULL_NAME, "w") as f: f.write(data)
        if i == 0: outputFiles[0] = OUTPUT_FULL_NAME
        if i == 1: outputFiles[1] = OUTPUT_FULL_NAME
        if i == 2: outputFiles[2] = OUTPUT_FULL_NAME
        
        runCipherParsing(scan_info, url_with_port, data, OUTPUT_FULL_NAME)
        #cleanup(OUTPUT_FULL_NAME)

    # Create the Observation, Implication and Recommendation depending on the vulnerable ciphers.
    observation = "*Observation*:\n\nThe affected resources present weaknesses in the configuration of the Transport Layer Security (TLS) protocol.\nThese weaknesses include:\n"
    implication = "*Implication:*\n\nA weak security configuration provides a malicious individual with more opportunities to successfully compromise the information transmitted over the encrypted channel.\nThe identified weaknesses expose the information to threats such as:\n"
    recommendation = "*Recommendation:*\n\n"
    listAllVulnsFound = []
    for i in range(len(listFoundCipherVulns)):
        if listFoundCipherVulns[i][3] not in listAllVulnsFound: listAllVulnsFound.append(listFoundCipherVulns[i][3])
    for i in range(len(listFoundCertificateVulns)):
        if listFoundCertificateVulns[i][3] not in listAllVulnsFound: listAllVulnsFound.append(listFoundCertificateVulns[i][3])
    # Observation...
    if any(item in ["SSL_VERSION_2_ENABLED", "SSL_VERSION_3_ENABLED","TLS_VERSION_1.0_ENABLED","TLS_VERSION_1.1_ENABLED"] for item in listAllVulnsFound):
        observation += "* Weak TLS/SSL version enabled:\n"
        if "SSL_VERSION_2_ENABLED" in listAllVulnsFound: observation += "** SSLv2 is enabled.\n"
        if "SSL_VERSION_3_ENABLED" in listAllVulnsFound: observation += "** SSLv3 is enabled.\n"
        if "TLS_VERSION_1.0_ENABLED" in listAllVulnsFound: observation += "** TLSv1.0 is enabled.\n"
        if "TLS_VERSION_1.1_ENABLED" in listAllVulnsFound: observation += "** TLSv1.1 is enabled.\n"
        observation += "\n"
    if any(item in ["WEAK_ENCRYPTION_CYPHERS", "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "EDH_CIPHERS_DETECTED", "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "TLS_BIRTHDAY_ATTACK_POSSIBLE"] for item in listAllVulnsFound):
        observation += "* Weak TLS cipher-suites supported:\n"
        if "WEAK_ENCRYPTION_CYPHERS" in listAllVulnsFound: observation += "** Short key length of cipher suites enabled (Less than 128 bits).\n"
        if "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK" in listAllVulnsFound: observation += "** Export grade RSA cipher suites enabled.\n"
        if "EDH_CIPHERS_DETECTED" in listAllVulnsFound: observation += "** Export grade EDH cipher suites enabled.\n"
        if "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS" in listAllVulnsFound: observation += "** RC4 encryption algorithm based cipher suites enabled.\n"
        if "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM" in listAllVulnsFound: observation += "** Short key length of DHE cipher suites (Less than 2048 bits).\n"
        if "TLS_BIRTHDAY_ATTACK_POSSIBLE" in listAllVulnsFound: observation += "** 64-bit block size cipher suites supported.\n"
        observation += "\n"
    if "TLS_POODLE_VULNERABILITY" in listAllVulnsFound: observation += "* TLS vulnerable to POODLE attack.\n\n"
    if "PERFECT_FORWARD_SECRECY_DISABLED" in listAllVulnsFound: observation += "* Perfect Forward Secrecy not supported / Inadequate Perfect Forward Secrecy support (DH enabled cipher-suites are not preferred).\n\n"
    if "SSL2_DROWN_ATACK" in listAllVulnsFound: observation += "* DROWN attack vulnerability (CVE-2016-0800).\n\n"
    # Implication...
    if "SSL_VERSION_2_ENABLED" in listAllVulnsFound or "SSL_VERSION_3_ENABLED":
        if "it-has-CBC-ciphers" in list_notes: implication += "* Security issues in the SSLv2 and SSLv3 protocols may allow a malicious individual to perform man-in-the-middle attacks. By forcing communication to a less secure level and then attempting to break the weak encryption, it may provide an opportunity to gain unauthorized access to data in transmission.\nFor reference, please see the following link: https://www.openssl.org/~bodo/ssl-poodle.pdf.\n"
        else:                                  implication += "* Security issues in the SSLv2 and SSLv3 protocols may allow a malicious individual to perform man-in-the-middle attacks. By forcing communication to a less secure level and then attempting to break the weak encryption, it may provide an opportunity to gain unauthorized access to data in transmission.\n"
    if "TLS_VERSION_1.0_ENABLED" in listAllVulnsFound or "TLS_VERSION_1.1_ENABLED" in listAllVulnsFound: implication += "* Security issues in the TLSv1.1 and earlier protocols may allow a malicious individual, who perform a man-in-the-middle attack, to predict the initialization vector blocks used to mask data prior to encryption.\n"
    if "TLS_BIRTHDAY_ATTACK_POSSIBLE" in listAllVulnsFound: implication += "* Certain block ciphers, such as 3DES and Blowfish have a block size of 64 bits. When used in CBC mode, these ciphers are known to be susceptible to the birthday attack. A malicious individual may attempt to inject a malicious Javascript to generate traffic and capture it to recover data.\nFor reference, please see the following link: https://sweet32.info/SWEET32_CCS16.pdf.\n"
    if "TLS_POODLE_VULNERABILITY" in listAllVulnsFound: implication += "* A TLS implementation which has been identified as vulnerable to POODLE may allow a malicious individual performing a man-in-the-middle attack against an application’s user, who is able to force this user’s browser to make multiple requests containing a specially crafted payload, to attempt an oracle-based attack on the communication, thus gaining unauthorized access to the data in transmission.\n"    
    if any(item in ["WEAK_ENCRYPTION_CYPHERS", "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK","EDH_CIPHERS_DETECTED"] for item in listAllVulnsFound):
        implication += "* Weak RSA's/EDH’s (Less than 512 bits) and encryption’s key length algorithms (Less than 128 bits) may allow a malicious individual to decrypt the data stream via a brute force approach, by forcing communication to a less secure level and then attempting to break the weak encryption, in order to gain unauthorized access to data.\n"
    if "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS" in listAllVulnsFound: implication += "* Security issues in the RC4 encryption algorithm that may allow a malicious individual to recover plaintext from a TLS connection.\nFor additional information, please refer to the following link: http://www.isg.rhul.ac.uk/tls/.\n"
    if "PERFECT_FORWARD_SECRECY_DISABLED" in listAllVulnsFound: implication += "* A malicious individual who manages to compromise the web server’s private key, would be able to leverage it in order to gain unauthorized access to sensitive information by breaking the encryption of previously intercepted communications.\n"
    if "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM" in listAllVulnsFound: implication += "* DHE cipher suites with 1024 bits or smaller primes may allow a malicious individual to attempt compromising the connection of sites sharing the same common prime numbers of the Diffie-Hellman key exchange.\n"
    if "SSL2_DROWN_ATACK" in listAllVulnsFound: implication += "* A strong TLS communication may be deciphered by a malicious individual performing a man-in-the-middle attack, if the affected host(s) share(s) the authentication RSA private key with another host that supports SSLv2 EXPORT-GRADE cipher-suites, by using the SSLv2 host as an RSA Padding Oracle.\nFor reference, please see the following link: https://drownattack.com/.\n"
    # Tactical Recommendation...
    recommendation += "Tactical Recommendation:\n\nManagement should consider reviewing if the observed configuration is required for business purposes. If not required, management should consider applying the following directives:\n"
    if any(item in ["SSL_VERSION_2_ENABLED", "SSL_VERSION_3_ENABLED","TLS_VERSION_1.0_ENABLED","TLS_VERSION_1.1_ENABLED"] for item in listAllVulnsFound):
        if "SSLv3-with-CBC-ciphers-found" in list_notes: recommendation += "* SSLv2, SSLv3, TLSv1.0 and TLSv1.1 should be disabled entirely (i.e. no longer supported), due to the fact that most up-to-date browsers will default to the highest protocol and cipher (i.e. TLSv1.2).\nFor additional information, please refer to the following link: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566.\n"
        else:                                            recommendation += "* SSLv2, SSLv3, TLSv1.0 and TLSv1.1 should be disabled entirely (i.e. no longer supported), due to the fact that most up-to-date browsers will default to the highest protocol and cipher (i.e. TLSv1.2).\n"
        if any(item in ["TLS_VERSION_1.0_ENABLED","TLS_VERSION_1.1_ENABLED"] for item in listAllVulnsFound):
            recommendation += "_Note: Disabling older protocols (such as TLSv1.0) may impact compatibility with certain devices and systems._\n"
    if any(item in ["WEAK_ENCRYPTION_CYPHERS", "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "EDH_CIPHERS_DETECTED", "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS"] for item in listAllVulnsFound):
        recommendation += "* Disable (i.e. do not support them) cipher suites that include Export grade RSA key, Export grade EDH key, weak encryption key lengths and RC4 encryption algorithms.\n"
    if "TLS_BIRTHDAY_ATTACK_POSSIBLE" in listAllVulnsFound: recommendation += "* Disable (i.e. do not support them) all 64-bit block ciphers.\n"
    if "TLS_POODLE_VULNERABILITY" in listAllVulnsFound: recommendation += "* Management should consider contact the transport layer security solution’s vendor, in order to get the relevant patches which address the TLS POODLE vulnerability.\n"
    if "PERFECT_FORWARD_SECRECY_DISABLED" in listAllVulnsFound: recommendation += "* Management should consider configuring the affected resources to support Diffie Hellman cipher-suites, and to actively select the cipher-suites offered by the TLS clients that ensure the communication is protected from later deciphering by this feature (i.e. by preferring strong Perfect Forward Secrecy compatible cipher-suites). Most up-to-date browsers will default to the highest perfect forward secrecy compatible protocol and cipher.\n"
    if "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM" in listAllVulnsFound: recommendation += "* Disable (i.e. do not support them) DHE cipher suites with 1024-bit or smaller primes, and replace them with a 2048-bit Diffie-Hellman group.\n"
    if "SSL2_DROWN_ATACK" in listAllVulnsFound: recommendation += "* Avoiding the sharing of keys with resources that do not match the TLS configuration secure standards, in particular with vulnerable SSLv2 hosts.\n"
    # Strategic Recommendation...
    recommendation += "\nStrategic Recommendation:\n\n* Management should consider reviewing their system configuration standards to ensure that TLS configurations are in line with organizational policies and ensure that TLS related configurations are consistent with all Internet-facing applications within the organization.\nFor additional information, please refer to the following link: https://cwe.mitre.org/data/definitions/326.html.\n"

    # Ahora retorno todo lo encontrado en CIPHERS...    
    strMessage = "Cipher vulnerabilities were found.\n\n\n" + observation + "\n\n" + implication + "\n\n" + recommendation + "\n\n*Detection of issues*:\n\n"
    vulnsAlreadyReported = []
    img_str_list = [False, False, False] # It will be [SSLSCANboolean, TestSSLboolean, SSLYZEboolean] (Example: Only SSLSCAN -> [True, False, False])
    for i in range(len(listFoundCipherVulns)):
        if listFoundCipherVulns[i][4].lower() == "sslscan": img_str_list[0] = True
        if listFoundCipherVulns[i][4].lower() == "testssl": img_str_list[1] = True
        if listFoundCipherVulns[i][4].lower() == "sslyze":  img_str_list[2] = True
        if listFoundCipherVulns[i][3] in vulnsAlreadyReported: continue # Si ya se reporto un issue con SSLSCAN
        else: vulnsAlreadyReported.append(listFoundCipherVulns[i][3])   # no volver a reportarlo con TestSSL...
        strMessage += listFoundCipherVulns[i][2] + "\n\n"
    if listFoundCipherVulns: add_vulnerability(scan_info, strMessage, isCipherVuln=True, img_str_list=img_str_list, outputFiles=outputFiles)
    
    # Create the Observation, Implication and Recommendation depending on the vulnerable certificate.
    observation = "*Observation*:\n\n"
    observation += "The SSL / TLS certificate in use is untrusted because it is " #<If expired: The SSL / TLS certificate in use has been expired since XXXXX>.<If SHA1: it was signed using a signature algorithm that is not secure. In particular, the affected resources are using SHA1 based certificates.>.\n"
    if "SELF_SIGNED_SSL_CERTIFICATES" in listAllVulnsFound: observation += "self-signed, "
    if "STILL_NOT_IMPLEMENTED_1" in listAllVulnsFound: observation += "was issued by an untrusted certificate authority (CA), "
    if "STILL_NOT_IMPLEMENTED_2" in listAllVulnsFound: observation += "the common name does not match the hostname, "
    if "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound: observation += "expired, "
    if any(item in ["SELF_SIGNED_SSL_CERTIFICATES", "EXPIRED_SSL_CERTIFICATE", "STILL_NOT_IMPLEMENTED_1", "STILL_NOT_IMPLEMENTED_2"] for item in listAllVulnsFound):
        observation = observation[:-2] + ". " # I remove tha last ", "
        with suppress(Exception): result = " and ".join(observation.rsplit(", ", 1)) # Replace LAST ", " with " and "
    if "SELF_SIGNED_SSL_CERTIFICATES" in listAllVulnsFound: observation += "Self-signed SSL / TLS certificates have not been issued by a trusted certificate authority (CA). "
    val = ""
    for i in range(len(listFoundCertificateVulns)):
        if listFoundCertificateVulns[i][3] == "EXPIRED_SSL_CERTIFICATE":
            val = listFoundCertificateVulns[i][2]; break
    if val and "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound:
        if "Not valid after: " in val: observation += "The SSL / TLS certificate in use has been expired since " + val.replace("Not valid after: ", "") + ". "
        elif "expired" in val and "--> " in val and ")" in val: observation += "The SSL / TLS certificate in use has been expired since " + val[val.rfind("-->")+4:-1] + ". "
    elif "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound:        observation += "The SSL / TLS certificate in use has been expired since <Please check manually>. "
    if "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION" in listAllVulnsFound:  observation += "It was signed using a signature algorithm that is not secure. In particular, the affected target is using SHA1 based certificates. "
    elif "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION" in listAllVulnsFound: observation += "It was signed using a signature algorithm that is not secure. In particular, the affected target is using MD5 based certificates. "
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound: observation += "Its RSA Key is weak (less than 2048-bit key). "
    if "TLS_ROBOT_ATTACK" in listAllVulnsFound and "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: observation += "Furthermore, the target is vulnerable to the TLS ROBOT Attack and TLS Renegotiation vulnerabilities. "
    elif "TLS_ROBOT_ATTACK" in listAllVulnsFound: observation += "Furthermore, the target is vulnerable to the TLS ROBOT Attack vulnerability."
    elif "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: observation += "Furthermore, the target is vulnerable to the TLS Renegotiation vulnerability."
    # Implication...
    implication = "*Implication*:\n\nSSL / TLS certificates are a prime protection mechanism against phishing attacks. Web browsers are likely to display a warning message to the user, as authenticity cannot be guaranteed. Untrusted SSL / TLS certificates would continue to trigger the warning messages on the browser, which may lead to users becoming accustomed to the warnings and to start ignoring them. As a result, these users are more susceptible to threats, such as pharming and phishing or Man-in-the-Middle attacks. "
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound: implication += "Furthermore, its RSA weak keys don’t have enough randomness to withstand brute-force cracking attempts. "
    if "TLS_ROBOT_ATTACK" in listAllVulnsFound: implication += "Furthermore, the TLS ROBOT attack allows RSA decryption and signing operations to be performed using the server's private key. "
    if "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: implication += "Furthermore, The vulnerable renegotiation feature allows a malicious individual (who has successfully performed a man-in-the-middle attack) to send an arbitrary HTTP request to the server, with the aim of performing unintended actions on behalf of victims. "
    # Recommendation
    recommendation = "*Recommendation*:\n\nManagement should consider replacing the current untrusted SSL / TLS certificates on the servers, with valid and trusted certificates that are bound to a specific hostname and issued by a trusted certificate authority (CA). "
    if "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound: recommendation += "Furthermore, management should consider reviewing their SSL / TLS certificate replacement policy and ensuring that renewal takes place prior to expiration dates. "
    if any(item in ["X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION"] for item in listAllVulnsFound):
        recommendation += "Furthermore, management should consider reviewing their SSL / TLS certificate replacement policy and ensuring that renewal takes place using the SHA256 algorithm instead of SHA1. "
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound: recommendation += "Furthermore, management should consider installing a server certificate signed with a public key length of at least 2048 bits. "
    if "TLS_ROBOT_ATTACK" in listAllVulnsFound: recommendation += "Furthermore, it is recommended to apply vendor patches and fully disable the use of RSA for encryption to remediate the TLS Robot vulnerability. "
    if "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: recommendation += "Furthermore, upgrading the identified affected software to the latest recommended version or apply all the relevant patches from the vendor relating to the insecure renegotiation issue. "
    recommendation += "Furthermore, management should consider reviewing their SSL / TLS certificate policy, to ensure that SSL / TLS related configuration is consistent with all web based applications within the organization.\n\n"

    # Ahora retorno todo lo encontrado en CERTIFICATES...
    vulnsAlreadyReported = []
    img_str_list = [False, False, False] # It will be [SSLSCANboolean, TestSSLboolean, SSLYZEboolean] (Example: Only SSLSCAN -> [True, False, False])
    strMessage = "Certificate vulnerabilities were found.\n\n\n" + observation + "\n\n" + implication + "\n\n" + recommendation + "\n\n*Detection of issues*:\n\n"
    for i in range(len(listFoundCertificateVulns)):
        if listFoundCertificateVulns[i][4].lower() == "sslscan": img_str_list[0] = True
        if listFoundCertificateVulns[i][4].lower() == "testssl": img_str_list[1] = True
        if listFoundCertificateVulns[i][4].lower() == "sslyze":  img_str_list[2] = True
        if listFoundCertificateVulns[i][3] in vulnsAlreadyReported: continue # Si ya se reporto un issue con SSLSCAN
        else: vulnsAlreadyReported.append(listFoundCertificateVulns[i][3])   # no volver a reportarlo con TestSSL...
        strMessage += listFoundCertificateVulns[i][2] + "\n\n"
    if listFoundCertificateVulns: add_vulnerability(scan_info, strMessage, isCertVuln=True, img_str_list=img_str_list, outputFiles=outputFiles)

    return

