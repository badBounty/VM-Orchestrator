# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import json
import xmltodict
import uuid
import xml
import copy
from datetime import datetime
import subprocess
import os
import re
from os.path import isdir, isfile, join

MODULE_NAME = 'SSL/TLS module'
MODULE_IDENTIFIER = 'tls_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-ssl-tls'

all_issues = []

def send_module_status_log(scan_info, status):
    print("Hola0")
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'arguments': scan_info
        })
    return

def handle_target(info):
    print("Hola1")
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
    print("Hola2")
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
    global all_issues

    # Declaro las strings de SELF-SIGNED
    self_issuer_list = "(\*|Server CA Test 1|Server CA Production 2|Server CA Production 1|nsng10406pap Intermediate CA|nldn11519pap Intermediate CA|Intermediate CA|UBS Server CA Test 3|Rohan Machado|Rohan_Machado|CROOT|SERVER|UBSIB_CA_PTE|a302-2831-4763.stm.swissbank.com)"
    # Defino headers...
    all_issues = []
    header = ["UNIQUE", "IP", "Port", "Protocol", "Hostname", "Vulnerability Name", "CVE", "Details", "Tool", "Evidence file name"]
    header_nmap = ["IP", "Hostname", "Port", "Protocol", "State", "Service", "Reason", "Version", "Script", "Evidence file name"]
    # regular expression
    re_port = "[1-9][0-9]{0,4}"
    re_protocol = "[tT][cC][pP]|[uU][dD][pP]"
    re_ip = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    re_hostname = "(?:[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]|[a-zA-Z0-9]{1,2})"
    re_domain = re_hostname + "(?:\." + re_hostname + ")*\.[a-zA-Z]{2,63}"
    # for SSLScan
    re_color = "(?:\\x1b\[3\dm)"
    re_color_green = "(?:\\x1b\[32m)"
    re_color_red = "(?:\\x1b\[31m)"
    re_color_end = "(?:\\x1b\[0m)"
    re_is_sslscan = "Connected to (" + re_ip + ")" + "\\n\\nTesting SSL server " + "?(" + re_ip + "|" + re_domain + ")" + "? on port " + "?(" + re_port + ")" + "?"
    # for TestSSL
    re_format_color = "(?:\\x1b\[\d;3\dm)"
    re_format = "(?:\\x1b\[\dm)"
    re_format_end = "(?:\\x1b\[m)"
    re_font_formats = "(?:\\x1b\[(?:\d)?(?:;3\d)?m)*"
    re_is_testssl = "Start \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} +-->> (" + re_ip + "):(" + re_port + ") \((" + re_ip + "|" + re_domain + ")\) <<--"
    # fos SSLYZE
    re_is_sslyze = "CHECKING HOST\(S\) AVAILABILITY"  # Parenthesys \( for REGEX
    # fos SSH-Audit
    re_is_sshaudit = "# general\\n\(gen\) banner:.+\\n\(gen\) software:.+\\n\(gen\) compatibility:.+\\n\(gen\) compression:"
    # for Nmap
    re_is_nmap = "Nmap scan report for ?(" + re_hostname + "|" + re_domain + ")? \(?(" + re_ip + ")\)?"

    # Unsafe SSH Cryptographic Settings
    # https://stribika.github.io/2015/01/04/secure-secure-shell.html
    # https://community.ipswitch.com/s/article/SSH-Weak-Key-Exchanges-Ciphers-HMAC-Sunset-on-3-17-2019
    re_unsafe_kex_list = "(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|ecdh-sha2-nistp256|ecdh-sha2-nistp384|ecdh-sha2-nistp521)"
    re_unsafe_key_list = "(ssh-dss)"
    re_unsafe_enc_list = "(3des-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc)"
    re_unsafe_mac_list = "(hmac-sha1|umac-32|umac-64-etm@openssh.com)"

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
        is_sslscan = re.search(re_is_sslscan, data)
        ip = is_sslscan.group(1)
        if re.search(re_domain, is_sslscan.group(2)): hostname = is_sslscan.group(2)
        else:                                         hostname = None
        port = is_sslscan.group(3)
        # Method version
        re_cipher = "([-\w]+)"
        re_supported_server_cipher = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv\d|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + re_cipher + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        if re.findall(re_supported_server_cipher, data):
            ciphers = re.findall(re_supported_server_cipher, data)
            # SSL_VERSION_2_ENABLED
            v = method_version("SSLv2", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "SSL_VERSION_2_ENABLED", None, v, "SSLScan", evidence)
            # SSL_VERSION_3_ENABLED >> CVE-2014-3566
            v = method_version("SSLv3", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "SSL_VERSION_3_ENABLED", "CVE-2014-3566", v, "SSLScan", evidence)
            # TLS_VERSION_1.0_ENABLED
            v = method_version("TLSv1.0", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.0_ENABLED", None, v, "SSLScan", evidence)
            # TLS_VERSION_1.1_ENABLED
            v = method_version("TLSv1.1", ciphers)
            if v: add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.1_ENABLED", None, v, "SSLScan", evidence)
            # WEAK_ENCRYPTION_CYPHERS >> Weak key length encryption algorithms (under 128 bits, except 112, 56 and 40 bits)
            cipher_lines = ""
            for cipher in ciphers:
                cipher = [item.strip() for item in cipher if item]
                if int(cipher[2]) < 128 and int(cipher[2]) != 112 and int(cipher[2]) != 56 and int(cipher[2]) != 40:
                    if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                    else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
            if cipher_lines: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS", None, cipher_lines, "SSLScan", evidence)
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        sweet32_ciphers="(IDEA-CBC-SHA|IDEA-CBC-MD5|RC2-CBC-MD5|KRB5-IDEA-CBC-SHA|KRB5-IDEA-CBC-MD5|ECDHE-RSA-DES-CBC3-SHA|ECDHE-ECDSA-DES-CBC3-SHA|SRP-DSS-3DES-EDE-CBC-SHA|SRP-RSA-3DES-EDE-CBC-SHA|SRP-3DES-EDE-CBC-SHA|EDH-RSA-DES-CBC3-SHA|EDH-DSS-DES-CBC3-SHA|DH-RSA-DES-CBC3-SHA|DH-DSS-DES-CBC3-SHA|AECDH-DES-CBC3-SHA|ADH-DES-CBC3-SHA|ECDH-RSA-DES-CBC3-SHA|ECDH-ECDSA-DES-CBC3-SHA|DES-CBC3-SHA|DES-CBC3-MD5|DES-CBC3-SHA|RSA-PSK-3DES-EDE-CBC-SHA|PSK-3DES-EDE-CBC-SHA|KRB5-DES-CBC3-SHA|KRB5-DES-CBC3-MD5|ECDHE-PSK-3DES-EDE-CBC-SHA|DHE-PSK-3DES-EDE-CBC-SHA|DES-CFB-M1|EXP1024-DHE-DSS-DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|EDH-DSS-DES-CBC-SHA|DH-RSA-DES-CBC-SHA|DH-DSS-DES-CBC-SHA|ADH-DES-CBC-SHA|EXP1024-DES-CBC-SHA|DES-CBC-SHA|EXP1024-RC2-CBC-MD5|DES-CBC-MD5|DES-CBC-SHA|KRB5-DES-CBC-SHA|KRB5-DES-CBC-MD5|EXP-EDH-RSA-DES-CBC-SHA|EXP-EDH-DSS-DES-CBC-SHA|EXP-ADH-DES-CBC-SHA|EXP-DES-CBC-SHA|EXP-RC2-CBC-MD5|EXP-RC2-CBC-MD5|EXP-KRB5-RC2-CBC-SHA|EXP-KRB5-DES-CBC-SHA|EXP-KRB5-RC2-CBC-MD5|EXP-KRB5-DES-CBC-MD5|EXP-DH-DSS-DES-CBC-SHA|EXP-DH-RSA-DES-CBC-SHA)"
        ssl2_sweet32_ciphers="(RC2-CBC-MD5|EXP-RC2-CBC-MD5|IDEA-CBC-MD5|DES-CBC-MD5|DES-CBC-SHA|DES-CBC3-MD5|DES-CBC3-SHA|DES-CFB-M1)"
        re_birthday_attack = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv3|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + sweet32_ciphers + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        re_ssl2_birthday_attack = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv2)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + sweet32_ciphers + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_birthday_attack, data)
        c_ssl2 = compromised_ciphers(re_birthday_attack, data)
        details = ""
        if c:
            if c_ssl2: details = c + "\n" + c_ssl2
            else:      details = c
        else:
            if c_ssl2: details = c_ssl2
        if details: add_issues(ip, port, "TCP", hostname, "TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", details, "SSLScan", evidence)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        anonymous_ciphers = "([-\w]*ADH[-\w]*|[-\w]*AECDH[-\w]*)"
        re_anonymous = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv\d|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + anonymous_ciphers + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_anonymous, data)
        if c: add_issues(ip, port, "TCP", hostname, "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, c, "SSLScan", evidence)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        rc4_ciphers = "([-\w]*RC4[-\w]*)"
        re_rc4 = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv\d|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + rc4_ciphers + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_rc4, data)
        if c: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, c, "SSLScan", evidence)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        exportrsa_cipher_list="(EXP1024-DES-CBC-SHA|EXP1024-RC2-CBC-MD5|EXP1024-RC4-SHA|EXP1024-RC4-MD5|EXP-EDH-RSA-DES-CBC-SHA|EXP-DH-RSA-DES-CBC-SHA|EXP-DES-CBC-SHA|EXP-RC2-CBC-MD5|EXP-RC4-MD5)"
        re_rsa_export_freak = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv\d|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + exportrsa_cipher_list + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_rsa_export_freak, data)
        if c: add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", c, "SSLScan", evidence)
        # SSL_TLS_WEAK_CBC_MODE_VULNERABILITY >> CVE-2011-3389 >> CBC Ciphers in SSLv3 and TLSv1.0 (Beast)
        cbc_cipher_list = "(EXP-RC2-CBC-MD5|IDEA-CBC-SHA|EXP-DES-CBC-SHA|DES-CBC-SHA|DES-CBC3-SHA|EXP-DH-DSS-DES-CBC-SHA|DH-DSS-DES-CBC-SHA|DH-DSS-DES-CBC3-SHA|EXP-DH-RSA-DES-CBC-SHA|DH-RSA-DES-CBC-SHA|DH-RSA-DES-CBC3-SHA|EXP-EDH-DSS-DES-CBC-SHA|EDH-DSS-DES-CBC-SHA|EDH-DSS-DES-CBC3-SHA|EXP-EDH-RSA-DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|EDH-RSA-DES-CBC3-SHA|EXP-ADH-DES-CBC-SHA|ADH-DES-CBC-SHA|ADH-DES-CBC3-SHA|KRB5-DES-CBC-SHA|KRB5-DES-CBC3-SHA|KRB5-IDEA-CBC-SHA|KRB5-DES-CBC-MD5|KRB5-DES-CBC3-MD5|KRB5-IDEA-CBC-MD5|EXP-KRB5-DES-CBC-SHA|EXP-KRB5-RC2-CBC-SHA|EXP-KRB5-DES-CBC-MD5|EXP-KRB5-RC2-CBC-MD5|AES128-SHA|DH-DSS-AES128-SHA|DH-RSA-AES128-SHA|DHE-DSS-AES128-SHA|DHE-RSA-AES128-SHA|ADH-AES128-SHA|AES256-SHA|DH-DSS-AES256-SHA|DH-RSA-AES256-SHA|DHE-DSS-AES256-SHA|DHE-RSA-AES256-SHA|ADH-AES256-SHA|CAMELLIA128-SHA|DH-DSS-CAMELLIA128-SHA|DH-RSA-CAMELLIA128-SHA|DHE-DSS-CAMELLIA128-SHA|DHE-RSA-CAMELLIA128-SHA|ADH-CAMELLIA128-SHA|EXP1024-RC2-CBC-MD5|EXP1024-DES-CBC-SHA|EXP1024-DHE-DSS-DES-CBC-SHA|CAMELLIA256-SHA|DH-DSS-CAMELLIA256-SHA|DH-RSA-CAMELLIA256-SHA|DHE-DSS-CAMELLIA256-SHA|DHE-RSA-CAMELLIA256-SHA|ADH-CAMELLIA256-SHA|PSK-3DES-EDE-CBC-SHA|PSK-AES128-CBC-SHA|PSK-AES256-CBC-SHA|DHE-PSK-3DES-EDE-CBC-SHA|DHE-PSK-AES128-CBC-SHA|DHE-PSK-AES256-CBC-SHA|RSA-PSK-3DES-EDE-CBC-SHA|RSA-PSK-AES128-CBC-SHA|RSA-PSK-AES256-CBC-SHA|SEED-SHA|DH-DSS-SEED-SHA|DH-RSA-SEED-SHA|DHE-DSS-SEED-SHA|DHE-RSA-SEED-SHA|ADH-SEED-SHA|PSK-AES128-CBC-SHA256|PSK-AES256-CBC-SHA384|DHE-PSK-AES128-CBC-SHA256|DHE-PSK-AES256-CBC-SHA384|RSA-PSK-AES128-CBC-SHA256|RSA-PSK-AES256-CBC-SHA384|ECDH-ECDSA-DES-CBC3-SHA|ECDH-ECDSA-AES128-SHA|ECDH-ECDSA-AES256-SHA|ECDHE-ECDSA-DES-CBC3-SHA|ECDHE-ECDSA-AES128-SHA|ECDHE-ECDSA-AES256-SHA|ECDH-RSA-DES-CBC3-SHA|ECDH-RSA-AES128-SHA|ECDH-RSA-AES256-SHA|ECDHE-RSA-DES-CBC3-SHA|ECDHE-RSA-AES128-SHA|ECDHE-RSA-AES256-SHA|AECDH-DES-CBC3-SHA|AECDH-AES128-SHA|AECDH-AES256-SHA|SRP-3DES-EDE-CBC-SHA|SRP-RSA-3DES-EDE-CBC-SHA|SRP-DSS-3DES-EDE-CBC-SHA|SRP-AES-128-CBC-SHA|SRP-RSA-AES-128-CBC-SHA|SRP-DSS-AES-128-CBC-SHA|SRP-AES-256-CBC-SHA|SRP-RSA-AES-256-CBC-SHA|SRP-DSS-AES-256-CBC-SHA|ECDHE-PSK-3DES-EDE-CBC-SHA|ECDHE-PSK-AES128-CBC-SHA|ECDHE-PSK-AES256-CBC-SHA|ECDHE-PSK-AES128-CBC-SHA256|ECDHE-PSK-AES256-CBC-SHA384|PSK-CAMELLIA128-SHA256|PSK-CAMELLIA256-SHA384|DHE-PSK-CAMELLIA128-SHA256|DHE-PSK-CAMELLIA256-SHA384|RSA-PSK-CAMELLIA128-SHA256|RSA-PSK-CAMELLIA256-SHA384|ECDHE-PSK-CAMELLIA128-SHA256|ECDHE-PSK-CAMELLIA256-SHA384)"
        re_weak_cbc_beast = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv3|TLSv1.0)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + cbc_cipher_list + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_weak_cbc_beast, data)
        if c: add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", c, "SSLScan", evidence)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> Incorrect TLS padding may be accepted when terminating TLS 1.1 and TLS 1.2 CBC cipher connections
        re_tls_poodle = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(TLSv1.1|TLSv1.2)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + cbc_cipher_list + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        c = compromised_ciphers(re_tls_poodle, data)
        if c: add_issues(ip, port, "TCP", hostname, "TLS_POODLE_VULNERABILITY", "CVE-2014-8730", c, "SSLScan", evidence)
        # SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM >> CVE-2015-4000 >> DHE_EXPORT Ciphers in TLS from 512 to 1024 bit keys
        exportdh_cipher_list = "(EXP1024-DHE-DSS-DES-CBC-SHA|EXP1024-DHE-DSS-RC4-SHA|EXP-EDH-RSA-DES-CBC-SHA|EXP-EDH-DSS-DES-CBC-SHA)"
        re_dhe_bit = re_color + "?(Preferred|Accepted)" + re_color_end + "? +" + re_color + "?(SSLv\d|TLSv1.\d)" + re_color_end + "? +" + re_color + "?(\d+)" + re_color_end + "? bits +" + re_color + "?" + exportdh_cipher_list + " +" + re_color_end + "? +([- \w]+)" + re_color + "?(\d+)?" + re_color_end + "? *(bits)?"
        if re.findall(re_dhe_bit, data):
            ciphers = re.findall(re_dhe_bit, data)
            cipher_lines = ""
            for cipher in ciphers:
                cipher = [item.strip() for item in cipher if item]
                if len(cipher) > 5:
                    if int(cipher[5]) <= 1024:
                        if not cipher_lines: cipher_lines = " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
                        else:                cipher_lines = cipher_lines + "\n" + " ".join(cipher[:3]) + " bits " + " ".join(cipher[3:])
            if cipher_lines: add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", cipher_lines, "SSLScan", evidence)
        # EXPIRED_SSL_CERTIFICATE >> It is compared with the current date
        re_cert_datetime = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( ?[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3]|[0-9]):([0-5][0-9]):([0-5][0-9]) (\d{4})"
        re_cert_datetime_expiration = "Not valid after: *" + re_color + "?" + re_cert_datetime + " GMT" + re_color_end + "?"
        if re.search(re_cert_datetime_expiration, data):
            dformat = "%b %d %H %M %S %Y"
            cert_dexp = re.search(re_cert_datetime_expiration, data)
            ###
            dnow = datetime.now()
            dexp = datetime.strptime( " ".join(cert_dexp.groups()) , dformat)
            if dexp < dnow: add_issues(ip, port, "TCP", hostname, "EXPIRED_SSL_CERTIFICATE", None, "Not valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", evidence)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months
            re_cert_datetime_since = "Not valid before: *" + re_color + "?" + re_cert_datetime + " GMT" + re_color_end + "?"
            if re.search(re_cert_datetime_since, data):
                cert_dsince = re.search(re_cert_datetime_since, data)
                dsince = datetime.strptime( " ".join(cert_dsince.groups()) , dformat)
                # find better way to calculate difference
                seconds_39_weeks = (365.25/12)*(24*60*60)*39
                if (dexp - dsince).total_seconds() > seconds_39_weeks:
                    add_issues(ip, port, "TCP", hostname, "SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, "Not valid before: " + cert_dsince.group(1) + " " + cert_dsince.group(2) + " " + ":".join(cert_dsince.groups()[2:5]) + " " + cert_dsince.group(6) + "\nNot valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", evidence)
        # SELF_SIGNED_SSL_CERTIFICATES >> If issuer is same as hostname we scanned, is * or is one of those listed in self_issuer_list, flag as self-signed
        re_subject = "Subject: +" + re_color + "?(.+)" + re_color_end + "?"
        re_issuer = "Issuer: +" + re_color + "?(.+)" + re_color_end + "?"
        if re.search(re_subject, data) and re.search(re_issuer, data):
            csub = re.search(re_subject, data)
            ciss = re.search(re_issuer, data)
            issuer = ciss.group(1).replace("\x1b[0m","")
            if re.search(self_issuer_list, issuer) or csub.group(1) == issuer:
                add_issues(ip, port, "TCP", hostname, "SELF_SIGNED_SSL_CERTIFICATES", None, "Subject: " + csub.group(1) + "\nIssuer: " + issuer, "SSLScan", evidence)
        # TLS_RENEGOTIATION_VULNERABILITY >> CVE-2009-3555
        re_renegotiation = re_color + "?(Insecure)" + re_color_end + "? session renegotiation supported"
        if re.search(re_renegotiation, data): add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", "Insecure session renegotiation supported", "SSLScan", evidence)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_compression = "Compression " + re_color + "?(enabled)" + re_color_end + "? (CRIME)"
        if re.search(re_compression, data): add_issues(ip, port, "TCP", hostname, "SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "Compression enabled (CRIME)", "SSLScan", evidence)
        # X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION >> CVE-2004-2761
        re_md5_rsa = "Signature Algorithm: " + re_color + "?(md5WithRSAEncryption)" + re_color_end + "?"
        if re.search(re_md5_rsa, data):
            md5_rsa = re.search(re_md5_rsa, data)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", "Signature Algorithm: " + md5_rsa.group(1), "SSLScan", evidence)
        # X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION
        re_sha1_rsa = "Signature Algorithm: " + re_color + "?(sha1WithRSAEncryption)" + re_color_end + "?"
        if re.search(re_sha1_rsa, data):
            sha1_rsa = re.search(re_sha1_rsa, data)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, "Signature Algorithm: " + sha1_rsa.group(1), "SSLScan", evidence)
        # SERVER_PUBLIC_KEY_TOO_SMALL >> RSA Key Strength: Menor a 2048
        re_rsa_key = "RSA Key Strength: +" + re_color + "?(\d+)" + re_color_end + "?"
        if re.search(re_rsa_key, data):
            rsa_key = re.search(re_rsa_key, data)
            if int(rsa_key.group(1)) < 2048:
                add_issues(ip, port, "TCP", hostname, "SERVER_PUBLIC_KEY_TOO_SMALL", None, "RSA Key Strength: " + rsa_key.group(1), "SSLScan", evidence)

    def testssl_parse(data, evidence):
        is_testssl = re.search(re_is_testssl, data)
        ip = is_testssl.group(1)
        port = is_testssl.group(2)
        if re.search(re_domain, is_testssl.group(3)): hostname = is_testssl.group(3)
        else:                                         hostname = None
        # SSL_VERSION_2_ENABLED
        re_testssl_sslv2 = "SSLv2 +" + re_format_end + "?" + re_format_color + "?(supported but couldn't detect a cipher and vulnerable to CVE-2015-3197|offered \(NOT ok\), also VULNERABLE to DROWN attack|offered \(NOT ok\)|CVE-2015-3197: supported but couldn't detect a cipher)" + re_format_end + "?([-\w ]+)?"
        if re.search(re_testssl_sslv2, data):
            testssl_sslv2 = re.search(re_testssl_sslv2, data)
            if testssl_sslv2.group(2): details = "SSLv2 " + testssl_sslv2.group(1) + testssl_sslv2.group(1)
            else:                      details = "SSLv2 " + testssl_sslv2.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_VERSION_2_ENABLED", None, details, "TestSSL", evidence)
        # SSL_VERSION_3_ENABLED >> CVE-2014-3566
        re_testssl_sslv3 = "SSLv3 +" + re_format_end + "?" + re_format_color + "?(offered \(NOT ok\)|server responded with higher version number \(TLSv1[.]+\) than requested by client \(NOT ok\)|server responded with version number [.]+ \(NOT ok\)|strange, server [.]+|supported but couldn't detect a cipher \(may need debugging\))" + re_format_end + "?"
        if re.search(re_testssl_sslv3, data):
            testssl_sslv3 = re.search(re_testssl_sslv3, data)
            details = "SSLv3 " + testssl_sslv3.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_VERSION_3_ENABLED", "CVE-2014-3566", details, "TestSSL", evidence)
        # TLS_VERSION_1.0_ENABLED
        re_testssl_tls10 = "TLS 1 +" + re_font_formats + "(offered" + re_font_formats + "(?: \(deprecated\))?|supported but couldn't detect a cipher \(may need debugging\))"
        if re.search(re_testssl_tls10, data):
            testssl_tls10 = re.search(re_testssl_tls10, data)
            details = "TLS 1.0 " + testssl_tls10.group(1).replace("\x1b[m","")
            add_issues(ip, port, "TCP", hostname, "TLS_VERSION_1.0_ENABLED", None, details, "TestSSL", evidence)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        re_testssl_anonymous = "Anonymous NULL Ciphers (no authentication) +" + re_format_end + "?" + re_format_color + "?(offered \(NOT ok\))" + re_format_end + "?"
        if re.search(re_testssl_anonymous, data):
            testssl_anonymous = re.search(re_testssl_anonymous, data)
            details = "Anonymous NULL Ciphers (no authentication) " + testssl_anonymous.group(1)
            add_issues(ip, port, "TCP", hostname, "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, details, "TestSSL", evidence)
        # X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION >> CVE-2004-2761
        re_testssl_md5_rsa = "(Signature Algorithm ) +" + re_format_end + "?" + re_format_color + "?(MD5)"
        if re.search(re_testssl_md5_rsa, data):
            testssl_md5_rsa = re.search(re_testssl_md5_rsa, data)
            details = ""
            for i in range(testssl_md5_rsa.lastindex):
                index = i + 1
                if testssl_md5_rsa.group(index):
                    if not details: details = testssl_md5_rsa.group(index)
                    else:           details = details + testssl_md5_rsa.group(index)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", details, "TestSSL", evidence)
        # X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION
        re_testssl_sha1_rsa = "(Signature Algorithm ) +" + re_format_end + "?" + re_format_color + "?(SHA1 with RSA|ECDSA with SHA1|DSA with SHA1|RSASSA-PSS with SHA1)" + re_format_end + "?( -- besides: users will receive a )?" + re_format_color + "?(strong browser WARNING)?"
        if re.search(re_testssl_sha1_rsa, data):
            testssl_sha1_rsa = re.search(re_testssl_sha1_rsa, data)
            details = ""
            for i in range(testssl_sha1_rsa.lastindex):
                index = i + 1
                if testssl_sha1_rsa.group(index):
                    if not details: details = testssl_sha1_rsa.group(index)
                    else:           details = details + testssl_sha1_rsa.group(index)
            add_issues(ip, port, "TCP", hostname, "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, details, "TestSSL", evidence)
        # SERVER_PUBLIC_KEY_TOO_SMALL >> EC Keys Strength: Menor a 224 >> RSA, DSA, DH Keys Strength: Menor a 2048
        re_testssl_key = "Server key size +" + re_format_end + "?([\w]+) " + re_format_color + "([\d]+)" + re_format_end + "? bits"
        if re.search(re_testssl_key, data):
            testssl_key = re.search(re_testssl_key, data)
            details = ""
            if testssl_key.group(1) == "EC" or testssl_key.group(1) == "ECDSA":
                if int(testssl_key.group(2)) < 224:  details = "Server key size " + testssl_key.group(1) + " " + testssl_key.group(2) + " bits"
            else:
                if int(testssl_key.group(2)) < 2048: details = "Server key size " + testssl_key.group(1) + " " + testssl_key.group(2) + " bits"
            if len(details) > 0:
                add_issues(ip, port, "TCP", hostname, "SERVER_PUBLIC_KEY_TOO_SMALL", None, details, "TestSSL", evidence)
        # SELF_SIGNED_SSL_CERTIFICATES >> If issuer is same as hostname we scanned, is * or is one of those listed in self_issuer_list, flag as self-signed
        re_issuer = "Issuer +" + re_format_end + "?(?:" + re_format_color + "?(self-signed \(NOT ok\))|" + re_format + "?(.+)" + re_format_end + "? \(" + re_format + "?(.+)" + re_format_end + "? from " + re_format + "?(\w+)" + re_format_end + "?\))"
        if re.search(re_issuer, data):
            ciss = re.search(re_issuer, data)
            details = ""
            if ciss.group(1): details = "Issuer " + ciss.group(1)
            else:
                issuer_found = ciss.group(2).replace("\x1b[m","")
                if re.search(self_issuer_list, issuer_found): details = "Issuer " + issuer_found
            if len(details) > 0: add_issues(ip, port, "TCP", hostname, "SELF_SIGNED_SSL_CERTIFICATES", None, details, "TestSSL", evidence)
        # EXPIRED_SSL_CERTIFICATE >> It is compared with the current date
        re_datetime = "([\d]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])"
        re_cert_datetime = "Certificate (?:Validity \(UTC\)|Expiration) +" + re_font_formats + "(?:[ <>=()\w\d]+|expired!?)" + re_font_formats + " \((?:UTC: )?" + re_datetime + " --> " + re_datetime + "(?: -[\d]{4})?\)(?:\\n +)?" + re_font_formats + "([>= \d\w]+)?"
        if re.search(re_cert_datetime, data):
            cert_datetime = re.search(re_cert_datetime, data)
            dformat = "%Y %m %d %H %M"
            nowdate = datetime.now()
            startdate = datetime.strptime(" ".join(cert_datetime.groups()[0:5]), dformat)
            enddate = datetime.strptime(" ".join(cert_datetime.groups()[5:10]) , dformat)
            if enddate < nowdate:
                details = "Certificate Validity (UTC) expired (" + "-".join(cert_datetime.groups()[0:3]) + " " + ":".join(cert_datetime.groups()[3:5]) + " --> " + "-".join(cert_datetime.groups()[5:8]) + " " + ":".join(cert_datetime.groups()[8:10]) + ")"
                add_issues(ip, port, "TCP", hostname, "EXPIRED_SSL_CERTIFICATE", None, details, "TestSSL", evidence)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months >> find better way to calculate difference
            seconds_39_weeks = (365.25/12)*(24*60*60)*39
            if (enddate - startdate).total_seconds() > seconds_39_weeks:
                details = "Certificate Validity (UTC) (" + "-".join(cert_datetime.groups()[0:3]) + " " + ":".join(cert_datetime.groups()[3:5]) + " --> " + "-".join(cert_datetime.groups()[5:8]) + " " + ":".join(cert_datetime.groups()[8:10]) + ")"
                if cert_datetime.group(11): details = details + "\n" + cert_datetime.group(11)
                add_issues(ip, port, "TCP", hostname, "SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, details, "TestSSL", evidence)
        # TLS_ROBOT_ATTACK
        re_robot = "ROBOT +" + re_format_end + "?" + re_format_color + "?VULNERABLE \(NOT ok\)" + re_format_end + "?([-\w ]+)?"
        if re.search(re_robot, data):
            robot = re.search(re_robot, data)
            if robot.group(1): details = "ROBOT VULNERABLE (NOT ok)" + robot.group(1)
            else:              details = "ROBOT VULNERABLE (NOT ok)"
            add_issues(ip, port, "TCP", hostname, "TLS_ROBOT_ATTACK", None, details, "TestSSL", evidence)
        # TLS_RENEGOTIATION_VULNERABILITY >> CVE-2009-3555
        re_renegotiation = "Secure Renegotiation " + re_font_formats + "\((RFC 5746|CVE-2009-3555)\) +" + re_font_formats + "(Not supported \/ )?VULNERABLE \(NOT ok\)"
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
        if details: add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", details, "TestSSL", evidence)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_testssl_compression = "CRIME, TLS " + re_font_formats + "\(CVE-2012-4929\) +" + re_font_formats + "(VULNERABLE [ :()\w]+)"
        if re.search(re_testssl_compression, data):
            testssl_compression = re.search(re_testssl_compression, data)
            add_issues(ip, port, "TCP", hostname, "SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "CRIME, TLS (CVE-2012-4929) " + testssl_compression.group(1), "TestSSL", evidence)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> TestSSL does not detect Poodle in TLS, only in SSL
        ''' EMPTY '''
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        re_testssl_sweet32 = "SWEET32" + re_format_end + "? \(CVE-2016-2183, CVE-2016-6329\) +" + re_format_color + "?VULNERABLE" + re_format_end + "?([\w]+)"
        if re.search(re_testssl_sweet32, data):
            testssl_sweet32 = re.search(re_testssl_sweet32, data)
            details = "SWEET32 (CVE-2016-2183, CVE-2016-6329) VULNERABLE, " + testssl_sweet32.group(1)
            add_issues(ip, port, "TCP", hostname, "TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", details, "TestSSL", evidence)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        re_testssl_freak = "FREAK" + re_format_end + "? \(CVE-2015-0204\) +" + re_format_color + "?VULNERABLE \(NOT ok\)" + re_format_end + "?([\w]+)"
        if re.search(re_testssl_freak, data):
            testssl_freak = re.search(re_testssl_freak, data)
            details = "FREAK (CVE-2015-0204) VULNERABLE (NOT ok), " + testssl_freak.group(1)
            add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", details, "TestSSL", evidence)
        # SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM >> CVE-2015-4000 >> DHE_EXPORT Ciphers in TLS from 512 to 1024 bit keys
        re_testssl_logjam = "LOGJAM" + re_format_end + "? \(CVE-2015-4000\)(?:[, \w]+)?" + re_format_color + "?(VULNERABLE \(NOT ok\):)?" + re_format_end + "?( uses DH EXPORT ciphers)?(?:\\n +)?" + re_format_color + "?(VULNERABLE \(NOT ok\):)" + re_format_end + "?( common prime:? )" + re_format + "?(.+)" + re_format_end + "?( \()" + re_format_color + "?([\d]+ bits)" + re_format_end + "?(\))(,)?(?:\\n +)?(but no DH EXPORT ciphers)?"
        if re.search(re_testssl_logjam, data):
            testssl_logjam = re.search(re_testssl_logjam, data)
            details = ""
            for i in range(testssl_logjam.lastindex):
                index = i + 1
                if testssl_logjam.group(index):
                    if not details: details = testssl_logjam.group(index)
                    else:
                        if testssl_logjam.group(index) == "VULNERABLE (NOT ok):": details = details + "\n" + testssl_logjam.group(index).replace("\x1b[m","")
                        else:                                                     details = details + testssl_logjam.group(index).replace("\x1b[m","")
            add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", details, "TestSSL", evidence)
        # SSL_TLS_WEAK_CBC_MODE_VULNERABILITY >> CVE-2011-3389 >> CBC Ciphers in SSLv3 and TLSv1.0 (Beast)
        re_testssl_beast = "BEAST" + re_format_end + "? \(CVE-2011-3389\) +([\w]+): " + re_format_color + "?([- \w]+)(?:\\n +)?([- \w]+)?" + re_format_end + "?(?:\\n +)?([\w]+)?(?:: )?" + re_format_color + "?([- \w]+)?(?:\\n +)?([- \w]+)?" + re_format_end + "?(?:\\n +)?" + re_format_color + "?(VULNERABLE)?" + re_format_end + "?([-:.\(\) \w]+)?"
        if re.search(re_testssl_beast, data):
            testssl_beast = re.search(re_testssl_beast, data)
            details = ""
            for i in range(testssl_beast.lastindex):
                index = i + 1
                if testssl_beast.group(index):
                    if not details: details = testssl_beast.group(index)
                    else:
                        if testssl_beast.group(index) == "SSL3" or testssl_beast.group(index) == "TLS1" or testssl_beast.group(index) == "VULNERABLE":
                            details = details + "\n" + testssl_beast.group(index)
                        else:
                            details = details + " " + testssl_beast.group(index)
            add_issues(ip, port, "TCP", hostname, "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", details, "TestSSL", evidence)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        re_testssl_rc4 = "RC4" + re_format_end + "? \(CVE-2013-2566, CVE-2015-2808\) +" + re_format_color + "?VULNERABLE \(NOT ok\): " + re_format_end + "?([- \w]+)"
        if re.search(re_testssl_rc4, data):
            testssl_rc4 = re.search(re_testssl_rc4, data)
            details = "RC4 (CVE-2013-2566, CVE-2015-2808) VULNERABLE (NOT ok): " + testssl_rc4.group(1)
            add_issues(ip, port, "TCP", hostname, "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, details, "TestSSL", evidence)

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
                    add_issues(ip, port, "TCP", hostname, "TLS_ROBOT_ATTACK", None, details, "SSLYZE", evidence)
        # SSLYZE RENEGOTIATION
        for i in range(len(tmpData)):
            if " * Session Renegotiation:" in tmpData[i]:
                if "Secure Renegotiation:" in tmpData[i+2] and "VULNERABLE" in tmpData[i+2]:
                    details = str(tmpData[i+2])[str(tmpData[i+2]).find("VULNERABLE"):].replace("\n", "")
                    add_issues(ip, port, "TCP", hostname, "TLS_RENEGOTIATION_VULNERABILITY", None, details, "SSLYZE", evidence)

    def add_issues(ip, port, protocol, hostname, vulnerability, cve, details, tool, evidence):
        unique = True
        if vulnerability == "SERVER_PUBLIC_KEY_TOO_SMALL" or vulnerability == "TLS_ROBOT_ATTACK" or vulnerability == "TLS_RENEGOTIATION_VULNERABILITY":
            firstly = "TestSSL"
        else:
            firstly = "SSLScan"
        for row in all_issues:
            if row[0] == ip and row[1] == port and row[2] == protocol and row[4] == vulnerability:
                unique = False
                if row[7].find(tool) == -1:
                    if tool == firstly:
                        if row[6].find(details) == -1: row[6] = details + "\n\n" + row[6]
                        row[7] = tool + ", " + row[7]
                        if row[8].find(evidence) == -1: row[8] = evidence + "\n" + row[8]
                    else:
                        if row[6].find(details) == -1: row[6] = row[6] + "\n\n" + details
                        row[7] = row[7] + ", " + tool
                        if row[8].find(evidence) == -1: row[8] = row[8] + "\n" + evidence
                break # Sale del FOR...
        if unique:
            if cve is None: cve = "" # Para evitar un error en ip+":"+port+":"+vulnerability+":"+cve (concatenate "str"+None)
            print("\n", str(ip), str(port), str(protocol), str(hostname), str(vulnerability), str(cve), str(details), str(tool), str(evidence))
            print("\nscan_info:", scan_info)
            checker(scan_info, url_with_port, str("ip")+str(port)+str(protocol)+str(hostname)+str(vulnerability)+str(cve)+str(details)+str(tool)+str(evidence), False)
            all_issues.append([ip+":"+port+":"+vulnerability+":"+cve, ip, port, protocol, hostname, vulnerability, cve, details, tool, evidence, " "]) # Edit DB (Agrego uno vacio al final para que no escape el filename de la tabla)
            if cipherParsingVerboseMode: print("Found " + str(vulnerability) + " in " + str(ip) + ":" + str(port))
            all_issues.sort(key=str)

    try: data = f.read()
    except:
        if cipherParsingVerboseMode: print(evidence + " can not be parsed")

    sslscan_positions = []
    for i in re.finditer(re_is_sslscan, data): sslscan_positions.append(i.start())
    if cipherParsingVerboseMode:
        if sslscan_positions: print("Results of the SSLScan tool found")

    testssl_positions = []
    for i in re.finditer(re_is_testssl, data):
        testssl_positions.append(i.start())
    if cipherParsingVerboseMode:
        if testssl_positions: print("Results of the TestSSL tool found")

    sslyze_positions = []
    for i in re.finditer(re_is_sslyze, data): sslyze_positions.append(i.start())
    if cipherParsingVerboseMode:
        if sslyze_positions: print("Results of the SSLYZE tool found")

    limits = sslscan_positions + testssl_positions + sslyze_positions
    if not limits:
        if cipherParsingVerboseMode: print(evidence + " contains results that could not be analyzed. The target could not be reached, it is the result of another tool (At the moment, only the SSLScan, TestSSL, SSH-Audit and Nmap tools are supported) or the format may not be correct for this analysis")
    limits.sort()

    msj_other = False
    for i in range(len(limits)):
        if i == len(limits)-1:
            lstart = limits[i]
            lend = len(data)
        else:
            lstart = limits[i]
            lend = limits[i+1]

        if re.search(re_is_sslscan, data[lstart:lend]):    sslscan_parse(data[lstart:lend], evidence)
        elif re.search(re_is_testssl, data[lstart:lend]):  testssl_parse(data[lstart:lend], evidence)
        elif re.search(re_is_sslyze, data[lstart:lend]):   sslyze_parse(data[lstart:lend], evidence)
        else:
            if not msj_other:
                if cipherParsingVerboseMode: print(evidence + " contains results that could not be analyzed. The target could not be reached, it is the result of another tool (At the moment, it only supports the SSLScan, TestSSL, SSH-Audit and Nmap tools) or the format may not be correct for this analysis")
                msj_other = True
    else:
        print("No issues found")
    '''
    progreso(currentValue, cntFiles, " completed.")
    listaFile = f.readlines()
    f.close()
    isSSLYZE = False
    lineaIPport = 0
    for i in range(len(listaFile)):
        # Si es SSLYZE...
        if "CHECKING HOST(S) AVAILABILITY" in listaFile[i]:
            isSSLYZE = True; lineaIPport = i+3; break
    try:
        if isSSLYZE:
            match = re.search('(.*):(\d{1,5})\s*=> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(listaFile[lineaIPport]).strip())
            if match:
                hostname = str(match.group(1))
                port = str(match.group(2))
                ip = str(match.group(3))
            else: raise ValueError
            if ip == hostname: hostname = ""
            # Si no hay un SSLv2 o SSLv3 antes reportado lo analizo...
            SSLv2reportadoAntes = False
            SSLv3reportadoAntes = False
            strSSLv2 = ""
            strSSLv3 = ""
            if not SSLv2reportadoAntes:
                for j in range(len(listaFile)):
                    with suppress(Exception):
                        if "* SSL 2.0 Cipher suites:" in listaFile[j] and "The server accepted" in listaFile[j+3]:
                            k = -1
                            while True:
                                k += 1 # Empieza en cero...
                                if str(listaFile[j+4+k]) == "\n": break # Si ya no hay mas ciphers, salgo...
                                strSSLv2 += str(listaFile[j+4+k]).strip() + "\n"
                                if k == len(listaFile): break
                    if strSSLv2:
                        print("SSLV2222222222222222"); break
                        nuevaFila = ws_results.max_row + 1
                        for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
                        if True:                                                ws_results.cell(row=nuevaFila, column=10).value = evidence
                        if True:                                                ws_results.cell(row=nuevaFila, column=3).value = port
                        if True:                                                ws_results.cell(row=nuevaFila, column=4).value = "TCP"
                        if "." in hostname and hostname != ip:                  ws_results.cell(row=nuevaFila, column=5).value = hostname
                        if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): ws_results.cell(row=nuevaFila, column=2).value = ip
                        if True:                                                ws_results.cell(row=nuevaFila, column=6).value = "SSL_VERSION_2_ENABLED"
                        if True:                                                ws_results.cell(row=nuevaFila, column=8).value = strSSLv2[:-1] # Quito el "\n" al final...
                        if True:                                                ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE'
                        if True:                                                ws_results.cell(row=nuevaFila, column=1).value = str(ip) + ":" + str(port) + ":" + "SSL_VERSION_2_ENABLED" + ":"
                        break # Dejo de analizar el archivo...
            if not SSLv3reportadoAntes:
                for j in range(len(listaFile)):
                    with suppress(Exception):
                        if "* SSL 3.0 Cipher suites:" in listaFile[j] and "The server accepted" in listaFile[j+3]:
                            k = -1
                            while True:
                                k += 1 # Empieza en cero...
                                if str(listaFile[j+4+k]) == "\n": break # Si ya no hay mas ciphers, salgo...
                                strSSLv3 += str(listaFile[j+4+k]).strip() + "\n"
                                if k == len(listaFile): break
                    if strSSLv3:
                        print("SSLV3333333333333333333"); break
                        nuevaFila = ws_results.max_row + 1
                        for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
                        if True:                                                ws_results.cell(row=nuevaFila, column=10).value = evidence
                        if True:                                                ws_results.cell(row=nuevaFila, column=3).value = port
                        if True:                                                ws_results.cell(row=nuevaFila, column=4).value = "TCP"
                        if "." in hostname and hostname != ip:                  ws_results.cell(row=nuevaFila, column=5).value = hostname
                        if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): ws_results.cell(row=nuevaFila, column=2).value = ip
                        if True:                                                ws_results.cell(row=nuevaFila, column=6).value = "SSL_VERSION_3_ENABLED"
                        if True:                                                ws_results.cell(row=nuevaFila, column=7).value = "CVE-2014-3566"
                        if True:                                                ws_results.cell(row=nuevaFila, column=8).value = strSSLv3[:-1] # Quito el "\n" al final...
                        if True:                                                ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE'
                        if True:                                                ws_results.cell(row=nuevaFila, column=1).value = str(ip) + ":" + str(port) + ":" + "SSL_VERSION_3_ENABLED:CVE-2014-3566"
                        break # Dejo de analizar el archivo...

    
    progreso(currentValue, cntFiles, " completed.")
    listaFile = f.readlines()
    f.close()
    isSSLSCAN = False
    lineaIPport = 0
    for i in range(len(listaFile)):
        # Si es SSLSCAN...
        if "Connected to " in listaFile[i]:
            with suppress(Exception): # [i+2]
                if "Testing SSL server" in listaFile[i+2]:
                    isSSLSCAN = True; lineaIPport = i+2; break
    try:
        if isSSLSCAN:
            try: ip = listaFile[lineaIPport-2].replace("Connected to ", "").replace("\n", "").replace(" ", "")
            except: ip = ""
            match = re.search('Testing SSL server (.*) on port (\d{1,5}) ', str(listaFile[lineaIPport]).replace("\n", "")+" ")
            if match:
                hostname = str(match.group(1))
                port = str(match.group(2))
            else: raise ValueError
            # Si no hay un SSLv2 o SSLv3 antes reportado lo analizo...
            SSLv2reportadoAntes = False
            SSLv3reportadoAntes = False
            for j in range(ws_results.max_row-1):
                print("SSLV4444444444444"); continue
                if ws_results.cell(row=j+2, column=4).value: # Si tiene valor en la columna "Protocol" es que es una linea de un issue activo ;)
                    if    ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value) and ws_results.cell(row=j+2, column=6).value == "SSL_VERSION_2_ENABLED": SSLv2reportadoAntes = True
                    if hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value) and ws_results.cell(row=j+2, column=6).value == "SSL_VERSION_2_ENABLED": SSLv2reportadoAntes = True
                    if    ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value) and ws_results.cell(row=j+2, column=6).value == "SSL_VERSION_3_ENABLED": SSLv3reportadoAntes = True
                    if hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value) and ws_results.cell(row=j+2, column=6).value == "SSL_VERSION_3_ENABLED": SSLv3reportadoAntes = True
            # Reviso si "SSLv2/3 enabled"
            for j in range(2):
                agregar = False
                if j == 0:
                    if SSLv2reportadoAntes: continue
                    # Si no se reportó SSLv2 antes me fijo si esta activo...
                    for k in range(len(listaFile)):
                        if listaFile[k].startswith("SSLv2") and "enabled" in listaFile[k]: agregar = True; break # Continuo y marco que esta activo...
                if j == 1:
                    if SSLv3reportadoAntes: continue
                    # Si no se reportó SSLv3 antes me fijo si esta activo...
                    for k in range(len(listaFile)):
                        if listaFile[k].startswith("SSLv3") and "enabled" in listaFile[k]: agregar = True; break # Continuo y marco que esta activo...
                if agregar:
                    nuevaFila = ws_results.max_row + 1
                    for h in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=h+1).border = thin_border
                    if True:                                                ws_results.cell(row=nuevaFila, column=10).value = evidence
                    if True:                                                ws_results.cell(row=nuevaFila, column=3).value = port
                    if "." in hostname and hostname != ip:                  ws_results.cell(row=nuevaFila, column=5).value = hostname
                    if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): ws_results.cell(row=nuevaFila, column=2).value = ip
                    if j == 0:                                              ws_results.cell(row=nuevaFila, column=6).value = "SSL_VERSION_2_ENABLED"
                    elif j == 1:                                            ws_results.cell(row=nuevaFila, column=6).value = "SSL_VERSION_3_ENABLED"
                    if True:                                                ws_results.cell(row=nuevaFila, column=8).value = "Ciphers not detected (try with SSLYZE --sslv2 --sslv3)"
                    if True:                                                ws_results.cell(row=nuevaFila, column=9).value = 'SSLSCAN'

    
    progreso(currentValue, cntFiles, " completed.")
    listaFile = f.readlines()
    f.close()
    isSSLSCAN = False
    isSSLYZE = False
    isTESTSSL = False
    lineaIPport = 0
    for i in range(len(listaFile)):
        # Si es SSLSCAN...
        if "Connected to " in listaFile[i]:
            with suppress(Exception): # [i+2]
                if "Testing SSL server" in listaFile[i+2]:
                    isSSLSCAN = True; lineaIPport = i+2; break
        # Si es SSLYZE...
        if "CHECKING HOST(S) AVAILABILITY" in listaFile[i]:
            isSSLYZE = True; lineaIPport = i+3; break
        # Si es TESTSSL...
        if "testssl.sh" in listaFile[i]:
            isTESTSSL = True; lineaIPport = i; break
    try:
        if isSSLYZE:
            match = re.search('(.*):(\d{1,5})\s*=> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(listaFile[lineaIPport]).strip())
            if match:
                hostname = str(match.group(1))
                port = str(match.group(2))
                ip = str(match.group(3))
            else: raise ValueError
            if ip == hostname: hostname = ""
            # Si hay una IP y/o Hostname valido en el archivo paso al siguiente file...
            for j in range(ws_results.max_row-1):
                if ws_results.cell(row=j+2, column=4).value: # Si tiene valor en la columna "Protocol" es que es una linea de un issue activo ;)
                    if    ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
                    if hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
            nuevaFila = ws_results.max_row + 1
            for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
            if True:                                                ws_results.cell(row=nuevaFila, column=10).value = evidence
            if True:                                                ws_results.cell(row=nuevaFila, column=3).value = port
            if "." in hostname and hostname != ip:                  ws_results.cell(row=nuevaFila, column=5).value = hostname
            if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): ws_results.cell(row=nuevaFila, column=2).value = ip
            if True:                                                ws_results.cell(row=nuevaFila, column=6).value = "No issue reported"
            if "SCAN COMPLETED IN " in str(listaFile):              ws_results.cell(row=nuevaFila, column=8).value = 'Reason 1: "Scan OK, no issues found"'
            else:                                                   ws_results.cell(row=nuevaFila, column=8).value = 'Reason 2: "Scan interrupted or no certificate information found"'
            if True:                                                ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE'
        elif isSSLSCAN:
            try: ip = listaFile[lineaIPport-2].replace("Connected to ", "").replace("\n", "").replace(" ", "")
            except: ip = ""
            match = re.search('Testing SSL server (.*) on port (\d{1,5}) ', str(listaFile[lineaIPport]).replace("\n", "")+" ")
            if match:
                hostname = str(match.group(1))
                port = str(match.group(2))
            else: raise ValueError
            # Si hay una IP y/o Hostname valido...
            for j in range(ws_results.max_row-1):
                if ws_results.cell(row=j+2, column=4).value: # Si tiene valor en la columna "Protocol" es que es una linea de un issue activo ;)
                    if    ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
                    if hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
            nuevaFila = ws_results.max_row + 1
            for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
            if True:                                                ws_results.cell(row=nuevaFila, column=10).value = evidence
            if True:                                                ws_results.cell(row=nuevaFila, column=3).value = port
            if "." in hostname and hostname != ip:                  ws_results.cell(row=nuevaFila, column=5).value = hostname
            if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): ws_results.cell(row=nuevaFila, column=2).value = ip
            if True:                                                ws_results.cell(row=nuevaFila, column=6).value = "No issue reported"
            if "Not valid after: " in str(listaFile):               ws_results.cell(row=nuevaFila, column=8).value = 'Reason 1: "Scan OK, no issues found"'
            else:                                                   ws_results.cell(row=nuevaFila, column=8).value = 'Reason 2: "Scan interrupted or no certificate information found"'
            if True:                                                ws_results.cell(row=nuevaFila, column=9).value = 'SSLSCAN'
        elif isTESTSSL:
            ip = ""; hostname = ""; port = ""
            for i in range(len(listaFile)):
                if "Start " in listaFile[i]:
                    match = re.search('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) \((.*)\)', listaFile[i])
                    if match:
                        ip = str(match.group(1))
                        port = str(match.group(2))
                        hostname = str(match.group(3))
                        if hostname == ip: hostname = ""
                        break
            if not ip and not hostname and not port: raise ValueError # Voy al siguiente archivo...
            for j in range(ws_results.max_row-1):
                if ws_results.cell(row=j+2, column=4).value: # Si tiene valor en la columna "Protocol" es que es una linea de un issue activo ;)
                    if    ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
                    if hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
            nuevaFila = ws_results.max_row + 1
            for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
            if True:                      ws_results.cell(row=nuevaFila, column=10).value = evidence
            if True:                      ws_results.cell(row=nuevaFila, column=3).value = port
            if "." in hostname:           ws_results.cell(row=nuevaFila, column=5).value = hostname
            if ip:                        ws_results.cell(row=nuevaFila, column=2).value = ip
            if True:                      ws_results.cell(row=nuevaFila, column=6).value = "No issue reported"
            if "Done " in str(listaFile): ws_results.cell(row=nuevaFila, column=8).value = 'Reason 1: "Scan OK, no issues found"'
            else:                         ws_results.cell(row=nuevaFila, column=8).value = 'Reason 2: "Scan interrupted or no certificate information found"'
            if True:                      ws_results.cell(row=nuevaFila, column=9).value = 'TestSSL'
        else: # Si no se detecto SSLYZE / SSLSCAN / TESTSSL -> Lo tomo de la primera linea ("Command") o del filename...
            ipOrHost = ""; port = ""; ip = ""; hostname = ""; takenFrom2ndLine = False
            lineaCommandAddedByPyTotal = ""
            for i in range(len(listaFile)):
                if listaFile[i].startswith("Command (added by PyTotal): "):
                    lineaCommandAddedByPyTotal = listaFile[i]
                    match = re.search(' (\S+):(\d{1,5}) >', str(listaFile[i]))
                    if match:
                        ip = str(match.group(1))
                        port = str(match.group(2))
                        if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip): hostname = ""
                        else:                                                   hostname = ip; ip = ""
                        takenFrom2ndLine = True
                        break
            if not takenFrom2ndLine:
                match = re.search('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,5})', evidence)
                if match:
                    ip = str(match.group(1))
                    port = str(match.group(2))
                else: raise ValueError
            for j in range(ws_results.max_row-1):
                if ws_results.cell(row=j+2, column=4).value: # Si tiene valor en la columna "Protocol" es que es una linea de un issue activo ;)
                    if                 ip    == str(ws_results.cell(row=j+2, column=2).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
                    if hostname and hostname == str(ws_results.cell(row=j+2, column=5).value) and str(port) == str(ws_results.cell(row=j+2, column=3).value): raise ValueError # Go to next file...
            if ip or hostname:
                nuevaFila = ws_results.max_row + 1
                for j in range(ws_results.max_column-1): ws_results.cell(row=nuevaFila, column=j+1).border = thin_border
                if True:     ws_results.cell(row=nuevaFila, column=10).value = evidence
                if True:     ws_results.cell(row=nuevaFila, column=3).value = port
                if hostname: ws_results.cell(row=nuevaFila, column=5).value = hostname
                if ip:       ws_results.cell(row=nuevaFila, column=2).value = ip
                if True:     ws_results.cell(row=nuevaFila, column=6).value = "No issue reported"
                if takenFrom2ndLine:
                    if "SSLSCAN" in lineaCommandAddedByPyTotal.upper():   ws_results.cell(row=nuevaFila, column=9).value = 'SSLSCAN (Potential)'
                    elif "SSLYZE" in lineaCommandAddedByPyTotal.upper():  ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE (Potential)'
                    elif "TESTSSL" in lineaCommandAddedByPyTotal.upper(): ws_results.cell(row=nuevaFila, column=9).value = 'TestSSL (Potential)'
                    else:
                        if "SSLSCAN" in evidence.upper():   ws_results.cell(row=nuevaFila, column=9).value = 'SSLSCAN (Potential)'
                        elif "SSLYZE" in evidence.upper():  ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE (Potential)'
                        elif "TESTSSL" in evidence.upper(): ws_results.cell(row=nuevaFila, column=9).value = 'TestSSL (Potential)'
                        else:                               ws_results.cell(row=nuevaFila, column=9).value = 'Unknown'
                    if ip and hostname: ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP, Hostname and Port taken from 2nd line of evidence.'
                    elif ip:            ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP and Port taken from 2nd line of evidence.'
                    elif hostname:      ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nHostname and Port taken from 2nd line of evidence.'
                    else:               ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP/Hostname/Port from filename?.'
                else:
                    if "SSLSCAN" in evidence.upper():   ws_results.cell(row=nuevaFila, column=9).value = 'SSLSCAN (Potential)'
                    elif "SSLYZE" in evidence.upper():  ws_results.cell(row=nuevaFila, column=9).value = 'SSLYZE (Potential)'
                    elif "TESTSSL" in evidence.upper(): ws_results.cell(row=nuevaFila, column=9).value = 'TestSSL (Potential)'
                    else:                               ws_results.cell(row=nuevaFila, column=9).value = 'Unknown'
                    if ip and hostname: ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP, Hostname and Port taken from filename of evidence.'
                    elif ip:            ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP and Port taken from filename of evidence.'
                    elif hostname:      ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nHostname and Port taken from filename of evidence.'
                    else:               ws_results.cell(row=nuevaFila, column=8).value = 'Reason 3: "Scan could not start" \nIP/Hostname/Port from filename?.'


    # Agrego espacios en la columna 11...
    for i in range(ws_results.max_row-1): ws_results.cell(row=i+2, column=11).value = " "

    # Agrego filtro en primera fila...
    ws_results.auto_filter.ref = "A1:J" + str(ws_results.max_row)
    ws_results.freeze_panes = "A2"

    # Guardo XLSX al final...
    if all_issues or nmap_result:
        if not nmap_result:
            with suppress(Exception): wb.remove(wb['NMAP'])
    elif not smartMode:
        input("\nNo se han encontrado issues de TLS. Archivo no creado. Presione ENTER para regresar..."); return True
    elif smartMode: return False
'''

def checker(scan_info, url_with_port, result, isJSON):
    timestamp = datetime.now()
    # testssl has a bunch of vulns, we could test more
    if isJSON:
        if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
            add_vulnerability(scan_info, "SSLv2 is available at %s" % url_with_port)
        elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
            add_vulnerability(scan_info, "SSLv3 is available at %s" % url_with_port)
        elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
            add_vulnerability(scan_info, "TLS1.0 is available at %s" % url_with_port)
    else:
        add_vulnerability(scan_info, "TLS issue in"+str(url_with_port)+"-->"+str(result))


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.SSL_TLS, scan_info, message)
    print("Encontrado:\nscan_info: " + str(scan_info) + "\nmessage: " + str(message))

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    vulnerability.id = mongo.add_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(scan_info, url, url_with_port):
    print("Hola3")

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'

    for i in range(3):
        random_filename = uuid.uuid4().hex
        OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + random_filename + '.json'
        cleanup(OUTPUT_FULL_NAME)

        # We first run the subprocess that creates the xml output file
        if i == 0: sp = subprocess.run(['sslscan', '--no-failed', '--no-colour', url_with_port], capture_output=True, timeout=500)
        if i == 1: sp = subprocess.run(['sslyze', '--reneg', '--robot', '--sslv2', '--sslv3', str(url_with_port)], capture_output=True, timeout=300)
        if i == 2: sp = subprocess.run([TOOL_DIR, '--fast', '--warnings=off', url_with_port], capture_output=True, timeout=500)

        data = sp.stdout.decode()

        if i == 0: tool = "SSLSCAN"
        if i == 1: tool = "SSLYZE"
        if i == 2: tool = "TestSSL"
        print("\n\nTool:", tool, "\ndata:\n", data, "\n\n")

        # Despues borrar esta parte de guardado de archivo (no usada)...
        with open(OUTPUT_FULL_NAME, "w") as f: f.write(data)

        if i == 0 or i == 1 or i == 2:
            runCipherParsing(scan_info, url_with_port, data, OUTPUT_FULL_NAME)
        elif i == 100000000000:
            try:
                with open(OUTPUT_FULL_NAME) as f:
                    results = json.load(f)
            except FileNotFoundError:
                print('SSL TLS module (TestSSL) reached timeout at %s' % url_with_port)

            for result in results:
                checker(scan_info, url_with_port, result, True)

    #cleanup(OUTPUT_FULL_NAME)
    return

