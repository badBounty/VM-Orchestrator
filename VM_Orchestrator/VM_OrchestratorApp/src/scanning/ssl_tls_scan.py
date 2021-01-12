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


def format_seconds_to_mmss(seconds):
    minutes = seconds // 60
    seconds %= 60
    return "%02i:%02i" % (minutes, seconds)


def runCipherParsing(scan_info, url_with_port, data):
    # Declaro las strings de SELF-SIGNED
    self_issuer_list = "(\*|Server CA Test 1|Server CA Production 2|Server CA Production 1|nsng10406pap Intermediate CA|nldn11519pap Intermediate CA|Intermediate CA|UBS Server CA Test 3|Rohan Machado|Rohan_Machado|CROOT|SERVER|UBSIB_CA_PTE|a302-2831-4763.stm.swissbank.com)"
    
    def sslscan_parse(data):
        #########################
        ####  CIPHER ISSUES  ####
        #########################
        # Function used to get ciphers lines affected by an specific issue...
        def compromised_ciphers(regex, data):
            data = str(data).splitlines() # It's better to treat it as a list
            cipher_lines = ""
            for line in data:
                if re.search(regex, line):
                    cipher_lines += line + "\n"
            return cipher_lines
        # SSL_VERSION_2_ENABLED
        v = compromised_ciphers("(Preferred|Accepted).*(SSLv2).*", data)
        if v: add_issues("SSL_VERSION_2_ENABLED", None, v, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_VERSION_3_ENABLED >> CVE-2014-3566
        v = compromised_ciphers("(Preferred|Accepted).*(SSLv3).*", data)
        if v: add_issues("SSL_VERSION_3_ENABLED", "CVE-2014-3566", v, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        if v and "CBC" in v and "SSLv3-with-CBC-ciphers-found" not in list_notes: list_notes.append("SSLv3-with-CBC-ciphers-found")
        # TLS_VERSION_1.0_ENABLED
        v = compromised_ciphers("(Preferred|Accepted).*(TLSv1.0).*", data)
        if v: add_issues("TLS_VERSION_1.0_ENABLED", None, v, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_VERSION_1.1_ENABLED
        v = compromised_ciphers("(Preferred|Accepted).*(TLSv1.1).*", data)
        if v: add_issues("TLS_VERSION_1.1_ENABLED", None, v, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS >> Weak key length encryption algorithms (under 128 bits)
        v = compromised_ciphers("(Preferred|Accepted).*(\d+)( bits)", data)
        if v:
            cipher_lines = ""
            for item in str(v).splitlines():
                with suppress(Exception):
                    if int(re.search("(Preferred|Accepted).*(\s)(\d{1,3})( bits)", item).group(3)) < 128:
                        cipher_lines += item + "\n"
            if cipher_lines:
                cipher_lines = cipher_lines[:-1] # Remove the last "\n"
                add_issues("WEAK_ENCRYPTION_CYPHERS", None, cipher_lines, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # [NOTE] Does it contain CBC ciphers?
        c = compromised_ciphers("(Preferred|Accepted).*(SSLv2|SSLv3).*(CBC).*", data)
        if c and "it-has-CBC-ciphers-in-SSLv2-3" not in list_notes: list_notes.append("it-has-CBC-ciphers-in-SSLv2-3")
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        re_birthday_attack = "(Preferred|Accepted).*(CBC)"
        c = compromised_ciphers(re_birthday_attack, data)
        if c: add_issues("TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        re_anonymous = "(Preferred|Accepted).*(SSLv\d|TLSv1.\d).*(ADH|AECDH)"
        c = compromised_ciphers(re_anonymous, data)
        if c: add_issues("SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        re_rc4 = "(Preferred|Accepted).*(RC4)"
        c = compromised_ciphers(re_rc4, data)
        if c: add_issues("WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        re_rsa_export_freak = "(Preferred|Accepted).*(EXP)"
        c = compromised_ciphers(re_rsa_export_freak, data)
        if c: add_issues("WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_CBC_MODE_VULNERABILITY >> CVE-2011-3389 >> CBC-Mode Ciphers in SSLv3 and TLSv1.0 (Beast)
        # Affected ciphers: CBC (DES 3DES AES) >> Source: https://www.acunetix.com/blog/web-security-zone/what-is-beast-attack/
        re_weak_cbc_beast = "(Preferred|Accepted).*(SSLv3|TLSv1.0).*(DES|CBC|AES)"
        c = compromised_ciphers(re_weak_cbc_beast, data)
        if c: add_issues("SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # EDH_CIPHERS_FOUND
        re_edh_ciphers = "(Preferred|Accepted).*(EDH)"
        c = compromised_ciphers(re_edh_ciphers, data)
        if c: add_issues("EDH_CIPHERS_DETECTED", "", c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> Incorrect TLS padding may be accepted when terminating TLS 1.1 and TLS 1.2 CBC cipher connections
        # This affects TLSv1.0, TLSv1.1 and TLSv1.2 >> Source: https://blog.qualys.com/product-tech/2019/04/22/zombie-poodle-and-goldendoodle-vulnerabilities
        POODLEciphers = "(Preferred|Accepted).*(TLSv1.0|TLSv1.1|TLSv1.2).*(AES|3DES)"
        c = compromised_ciphers(POODLEciphers, data)
        if c: add_issues("TLS_POODLE_VULNERABILITY", "CVE-2014-8730", c, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM >> CVE-2015-4000 >> DHE_EXPORT Ciphers in TLS from 512 to 1024 bit keys
        v = compromised_ciphers("(Preferred|Accepted).*(DHE).*\s(\d{1,4})( bits)", data)
        if v:
            cipher_lines = ""
            for item in str(v).splitlines():
                with suppress(Exception):
                    if 512 <= int(re.search("(Preferred|Accepted).*(DHE).*\s(\d{1,4})( bits)", item).group(3)) <= 1024:
                        cipher_lines += item + "\n"
            if cipher_lines:
                cipher_lines = cipher_lines[:-1] # Remove the last "\n"
                add_issues("SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", cipher_lines, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        ##########################
        ### CERTIFICATE ISSUES ###
        ##########################
        # EXPIRED_SSL_CERTIFICATE >> It is compared with the current date...
        re_cert_datetime = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( ?[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3]|[0-9]):([0-5][0-9]):([0-5][0-9]) (\d{4})"
        re_cert_datetime_expiration = "Not valid after: *.*?" + re_cert_datetime + " GMT.*?"
        if re.search(re_cert_datetime_expiration, data):
            dformat = "%b %d %H %M %S %Y"
            cert_dexp = re.search(re_cert_datetime_expiration, data)
            dnow = datetime.now()
            dexp = datetime.strptime( " ".join(cert_dexp.groups()) , dformat)
            if dexp < dnow: add_issues("EXPIRED_SSL_CERTIFICATE", None, "Not valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months
            re_cert_datetime_since = "Not valid before: *.*?" + re_cert_datetime + " GMT.*?"
            if re.search(re_cert_datetime_since, data):
                cert_dsince = re.search(re_cert_datetime_since, data)
                dsince = datetime.strptime( " ".join(cert_dsince.groups()) , dformat)
                seconds_39_weeks = (365.25/12)*(24*60*60)*39
                if (dexp - dsince).total_seconds() > seconds_39_weeks:
                    add_issues("SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, "Not valid before: " + cert_dsince.group(1) + " " + cert_dsince.group(2) + " " + ":".join(cert_dsince.groups()[2:5]) + " " + cert_dsince.group(6) + "\nNot valid after: " + cert_dexp.group(1) + " " + cert_dexp.group(2) + " " + ":".join(cert_dexp.groups()[2:5]) + " " + cert_dexp.group(6), "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SELF_SIGNED_SSL_CERTIFICATES
        with suppress(Exception): # By creating the one-liners they fail with an exception if not vulnerable.
            subject = re.search("(Subject:)(.*)", data).group(2).strip()
            issuer = re.search("(Issuer:)(.*)", data).group(2).strip()
            details = "Subject: " + subject + "\nIssuer: " + issuer
            if issuer == subject:
                add_issues("SELF_SIGNED_SSL_CERTIFICATES", None, details, "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_RENEGOTIATION_VULNERABILITY >> CVE-2009-3555
        re_renegotiation = ".*?(Insecure).*? session renegotiation supported"
        if re.search(re_renegotiation, data): add_issues("TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", "Insecure session renegotiation supported", "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_compression = "Compression .*?(enabled).*? (CRIME)"
        if re.search(re_compression, data): add_issues("SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "Compression enabled (CRIME)", "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION >> CVE-2004-2761
        re_md5_rsa = "Signature Algorithm: .*?(md5WithRSAEncryption).*?"
        if re.search(re_md5_rsa, data):
            md5_rsa = re.search(re_md5_rsa, data)
            add_issues("X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", "Signature Algorithm: " + md5_rsa.group(1), "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION
        re_sha1_rsa = "Signature Algorithm: .*?(sha1WithRSAEncryption).*?"
        if re.search(re_sha1_rsa, data):
            sha1_rsa = re.search(re_sha1_rsa, data)
            add_issues("X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, "Signature Algorithm: " + sha1_rsa.group(1), "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SERVER_PUBLIC_KEY_TOO_SMALL >> RSA Key Strength: Menor a 2048
        re_rsa_key = "RSA Key Strength:.*?(\d{1,4}).*?"
        rePubKey = re.search(re_rsa_key, data)
        if rePubKey:
            if int(rePubKey.group(1)) < 2048:
                add_issues("SERVER_PUBLIC_KEY_TOO_SMALL", None, "RSA Key Strength: " + rePubKey.group(1), "SSLScan", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)

    def testssl_parse(data):
        data = data.replace("\t", " ")
        # SSL_VERSION_2_ENABLED
        re_testssl_sslv2 = "SSLv2 .*?(supported but couldn't detect a cipher and vulnerable to CVE-2015-3197|offered \(NOT ok\), also VULNERABLE to DROWN attack|offered \(NOT ok\)|CVE-2015-3197: supported but couldn't detect a cipher).*?([-\w ]+)?"
        if re.search(re_testssl_sslv2, data):
            testssl_sslv2 = re.search(re_testssl_sslv2, data)
            if testssl_sslv2.group(2): details = "SSLv2 " + testssl_sslv2.group(1) + testssl_sslv2.group(1)
            else:                      details = "SSLv2 " + testssl_sslv2.group(1)
            add_issues("SSL_VERSION_2_ENABLED", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            if "also VULNERABLE to DROWN attack" in details:
                add_issues("SSL2_DROWN_ATACK", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_VERSION_3_ENABLED >> CVE-2014-3566
        re_testssl_sslv3 = "SSLv3 .*?(offered \(NOT ok\)|server responded with higher version number \(TLSv1[.]+\) than requested by client \(NOT ok\)|server responded with version number [.]+ \(NOT ok\)|strange, server [.]+|supported but couldn't detect a cipher \(may need debugging\)).*?"
        if re.search(re_testssl_sslv3, data):
            testssl_sslv3 = re.search(re_testssl_sslv3, data)
            details = "SSLv3 " + testssl_sslv3.group(1)
            add_issues("SSL_VERSION_3_ENABLED", "CVE-2014-3566", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_VERSION_1.0_ENABLED
        re_testssl_tls10 = "TLS 1\s.*(offered.*(?: \(deprecated\))?|supported but couldn't detect a cipher \(may need debugging\))"
        if re.search(re_testssl_tls10, data):
            testssl_tls10 = re.search(re_testssl_tls10, data)
            if "not offered" not in str(testssl_tls10).lower():
                details = "TLS 1.0 " + testssl_tls10.group(1)
                add_issues("TLS_VERSION_1.0_ENABLED", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_VERSION_1.1_ENABLED
        re_testssl_tls11 = "TLS 1.1 .*(offered.*(?: \(deprecated\))?|supported but couldn't detect a cipher \(may need debugging\))"
        if re.search(re_testssl_tls11, data):
            re_testssl_tls11 = re.search(re_testssl_tls11, data)
            if "not offered" not in str(re_testssl_tls11).lower():
                details = "TLS 1.1 " + re_testssl_tls11.group(1)
                add_issues("TLS_VERSION_1.0_ENABLED", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED >> ADH and AECDH ciphers
        re_testssl_anonymous = "Anonymous NULL Ciphers (no authentication) .*?(offered \(NOT ok\)).*?"
        if re.search(re_testssl_anonymous, data):
            testssl_anonymous = re.search(re_testssl_anonymous, data)
            details = "Anonymous NULL Ciphers (no authentication) " + testssl_anonymous.group(1)
            add_issues("SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
            add_issues("X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION", "CVE-2004-2761", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
            add_issues("X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
                add_issues("SERVER_PUBLIC_KEY_TOO_SMALL", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SELF_SIGNED_SSL_CERTIFICATES >> If issuer is same as hostname we scanned, is * or is one of those listed in self_issuer_list, flag as self-signed
        re_issuer = "Issuer .*?(?:.*?(self-signed \(NOT ok\))|.*?(.+).*? \(.*?(.+).*? from .*?(\w+).*?\))"
        if re.search(re_issuer, data):
            ciss = re.search(re_issuer, data)
            details = ""
            if ciss.group(1): details = "Issuer " + ciss.group(1)
            else:
                issuer_found = ciss.group(2)
                if re.search(self_issuer_list, issuer_found): details = "Issuer " + issuer_found
            if len(details) > 0: add_issues("SELF_SIGNED_SSL_CERTIFICATES", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
                add_issues("EXPIRED_SSL_CERTIFICATE", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
            # SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE >> Validity period greater than 39 months >> find better way to calculate difference
            seconds_39_weeks = (365.25/12)*(24*60*60)*39
            if (enddate - startdate).total_seconds() > seconds_39_weeks:
                details = "Certificate Validity (UTC) (" + "-".join(cert_datetime.groups()[0:3]) + " " + ":".join(cert_datetime.groups()[3:5]) + " --> " + "-".join(cert_datetime.groups()[5:8]) + " " + ":".join(cert_datetime.groups()[8:10]) + ")"
                if cert_datetime.group(11): details = details + "\n" + cert_datetime.group(11)
                add_issues("SSL_CERTIFICATE_INVALID_MAXIMUM_VALIDITY_DATE", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_ROBOT_ATTACK
        re_robot = "ROBOT .*?VULNERABLE \(NOT ok\).*?([-\w ]+)?"
        if re.search(re_robot, data):
            robot = re.search(re_robot, data)
            if robot.group(1): details = "ROBOT VULNERABLE (NOT ok)" + robot.group(1)
            else:              details = "ROBOT VULNERABLE (NOT ok)"
            add_issues("TLS_ROBOT_ATTACK", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
        if details: add_issues("TLS_RENEGOTIATION_VULNERABILITY", "CVE-2009-3555", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY >> CVE-2012-4929
        re_testssl_compression = "CRIME, TLS .*\(CVE-2012-4929\) .*(VULNERABLE [ :()\w]+)"
        if re.search(re_testssl_compression, data):
            testssl_compression = re.search(re_testssl_compression, data)
            add_issues("SSL/TLS_COMPRESSION_ALGORITHM_INFORMATION_LEAKAGE_VULNERABILITY", "CVE-2012-4929", "CRIME, TLS (CVE-2012-4929) " + testssl_compression.group(1), "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # TLS_POODLE_VULNERABILITY >> CVE-2014-8730 >> TestSSL does not detect Poodle in TLS, only in SSL
        ''' EMPTY '''
        # TLS_BIRTHDAY_ATTACK_POSSIBLE >> CVE-2016-2183 >> 64-bit block ciphers (Sweet32)
        re_testssl_sweet32 = "SWEET32.*? \(CVE-2016-2183, CVE-2016-6329\) +.*?VULNERABLE(.*)"
        if re.search(re_testssl_sweet32, data):
            testssl_sweet32 = re.search(re_testssl_sweet32, data)
            details = "SWEET32 (CVE-2016-2183, CVE-2016-6329) VULNERABLE" + testssl_sweet32.group(1)
            add_issues("TLS_BIRTHDAY_ATTACK_POSSIBLE", "CVE-2016-2183", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK >> CVE-2015-0204 >> Factoring RSA Export Keys (FREAK)
        re_testssl_freak = "FREAK.*? \(CVE-2015-0204\) +.*?VULNERABLE \(NOT ok\).*?([\w]+)"
        if re.search(re_testssl_freak, data):
            testssl_freak = re.search(re_testssl_freak, data)
            details = "FREAK (CVE-2015-0204) VULNERABLE (NOT ok), " + testssl_freak.group(1)
            add_issues("WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK", "CVE-2015-0204", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
            add_issues("SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM", "CVE-2015-4000", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
            add_issues("SSL_TLS_WEAK_CBC_MODE_VULNERABILITY", "CVE-2011-3389", details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS
        re_testssl_rc4 = "RC4.*? \(CVE-2013-2566, CVE-2015-2808\) +.*?VULNERABLE \(NOT ok\): .*?([- \w]+)"
        if re.search(re_testssl_rc4, data):
            testssl_rc4 = re.search(re_testssl_rc4, data)
            details = "RC4 (CVE-2013-2566, CVE-2015-2808) VULNERABLE (NOT ok): " + testssl_rc4.group(1)
            add_issues("WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # PERFECT_FORWARD_SECRECY_DISABLED
        if "No ciphers supporting Forward Secrecy (FS) offered" in data:
            details = "No ciphers supporting Forward Secrecy (FS) offered"
            add_issues("PERFECT_FORWARD_SECRECY_DISABLED", None, details, "TestSSL", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)

    def sslyze_parse(data):
        tmpData = (''.join(data)).split("\n")
        # SSLYZE ROBOT
        for i in range(len(tmpData)):
            if " * ROBOT Attack:" in tmpData[i]:
                if "VULNERABLE" in tmpData[i+1]:
                    details = str(tmpData[i+1])[str(tmpData[i+1]).find("VULNERABLE"):].replace("\n", "")
                    add_issues("TLS_ROBOT_ATTACK", None, details, "SSLYZE", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        # SSLYZE RENEGOTIATION
        for i in range(len(tmpData)):
            if " * Session Renegotiation:" in tmpData[i]:
                if "Secure Renegotiation:" in tmpData[i+2] and "VULNERABLE" in tmpData[i+2]:
                    details = str(tmpData[i+2])[str(tmpData[i+2]).find("VULNERABLE"):].replace("\n", "")
                    add_issues("TLS_RENEGOTIATION_VULNERABILITY", None, details, "SSLYZE", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
                    add_issues("SSL_VERSION_2_ENABLED", None, details, "SSLYZE", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
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
                    add_issues("SSL_VERSION_3_ENABLED", None, details, "SSLYZE", url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns)
        import time; time.sleep(10)
                 
    def add_issues(vulnerability, cve, details, tool, url_with_port, data, listFoundCipherVulns, listFoundCertificateVulns):
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
        elif vulnerability == "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION": message = "The certificate is using SHA1 signature which is considered insecure:\n" + details
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
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK": message = "The following ciphers are vulnerable to the FREAK vulnerability:\n" + details
            elif vulnerability == "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS": message = "The following ciphers are vulnerable (RC4):\n" + details
            elif vulnerability == "SSL_TLS_WEAK_CBC_MODE_VULNERABILITY": message = "The following SSLv3/TLSv1.0 ciphers are vulnerable to the BEAST vulnerability:\n" + details
            elif vulnerability == "EDH_CIPHERS_DETECTED": message = "The following EDH ciphers were found:\n" + details
            elif vulnerability == "TLS_POODLE_VULNERABILITY": message = "The following TLS ciphers could lead to TLS Poodle vulnerabilities (ZombiePOODLE/GoldenPOODLE):\n" + details
            elif vulnerability == "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM": message = "The following ciphers are vulnerable to LOGJAM (DHE_EXPORT ciphers with 512 to 1024 bit keys):\n" + details
            elif vulnerability == "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED": message = "The following ciphers are vulnerable to \"Server anonymous authentication\" (ADH and AECDH ciphers):\n" + details
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
            print("Warning, coding error, vulnerability \"" + str(vulnerability) + "\" not correctly assigned."); return
        # If it is a CERTIFICATE vuln or CIPHER vuln, it will be added into its corresponding list...
        if isCertificateVuln: listFoundCertificateVulns.append([scan_info, url_with_port, message, vulnerability, tool])
        if isCipherVuln:      listFoundCipherVulns.append([scan_info, url_with_port, message, vulnerability, tool])

    re_is_sslscan = "Connected to .*\\n\\nTesting SSL server .* on port .*"
    re_is_sslyze  = ".*CHECKING HOST\(S\) AVAILABILITY.*"
    re_is_testssl = ".*Start \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*-->>.*<<--.*"
    
    if re.search(re_is_sslscan, data):   sslscan_parse(data)
    elif re.search(re_is_sslyze, data):  sslyze_parse(data)
    elif re.search(re_is_testssl, data): testssl_parse(data)


def cleanup(path):
    with suppress(FileNotFoundError): os.remove(path)


def add_vulnerability(scan_info, message, isCipherVuln=False, isCertVuln=False, img_str_list=None, listData=None):
    if isCipherVuln: vulnerability = Vulnerability(constants.SSL_TLS_CIPHERS, scan_info, message)
    elif isCertVuln: vulnerability = Vulnerability(constants.SSL_TLS_CERTIFICATE, scan_info, message)
    else: return # If it's neither declared as CIPHER VULN nor as CERT VULN leave function...
    if img_str_list:
        for i in range(len(img_str_list)): # img_str_list tells which tools had results... [True, False, False] means only SSLSCAN brought active vulnerabilities
            with suppress(Exception):
                if img_str_list[i] == False: continue # if no issues were found with a tool, continue...
                img_str = image_creator.create_image_from_string(listData[i])
                vulnerability.add_image_string(img_str)
                ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
                output_dir = ROOT_DIR+'/tools_output/' + str(uuid.uuid4().hex) + '.png'
                im = Image.open(BytesIO(base64.b64decode(img_str)))
                im.save(output_dir, 'PNG')
                if i == 0: vulnerability.add_attachment(output_dir, 'SSLSCAN-result.png')
                if i == 1: vulnerability.add_attachment(output_dir, 'TestSSL-result.png')
                if i == 2: vulnerability.add_attachment(output_dir, 'SSLYZE-result.png')

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    vulnerability.id = mongo.add_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)
    # Borro los archivos temporales...
    with suppress(Exception): os.remove(output_dir)


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(scan_info, url, url_with_port):
    global all_issues; all_issues = []
    global list_notes; list_notes = []
    global listFoundCipherVulns; listFoundCipherVulns = []
    global listFoundCertificateVulns; listFoundCertificateVulns = []

    listData = ["", "", ""]

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'

    for i in range(3):
        random_filename = uuid.uuid4().hex
        OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + random_filename + '.txt'

        data = "" # Just leave it here.
        if True:
            setTimeout = 450 # 7.5 minutes
            if i == 0:
                startTime = datetime.now()
                try: sp = subprocess.run(['sslscan', '--no-failed', '--no-colour', url_with_port], capture_output=True, timeout=setTimeout)
                except subprocess.TimeoutExpired: print("Module SSL/TLS timed out ("+str(setTimeout)+"s) when running SSLSCAN on " + str(url_with_port) + " (canceled tool 1/3)"); continue
                except Exception as e: print("Module SSL/TLS failed on SSLSCAN stage (tool 1/3). Error: " + str(e)); continue
                print("Module SSL/TLS finished running SSLSCAN on " + str(url_with_port) + " (tool 1/3) -> Elapsed time: " + format_seconds_to_mmss((datetime.now()-startTime).total_seconds()))
            if i == 1:
                startTime = datetime.now() # IN NEXT LINE -> Parameters used: -f (Perfect Forward Secrecy) & -p (SSL/TLS protocols) & -S (certificate information) & -h (header information) & -U (ALL VULNERABILITIES)
                try: sp = subprocess.run([TOOL_DIR, '-f', '-p', '-S', '-h', '-U', '--color', '0', '--warnings=off', "--ip", "one", url_with_port], capture_output=True, timeout=setTimeout)
                except subprocess.TimeoutExpired: print("Module SSL/TLS timed out ("+str(setTimeout)+"s) when running TESTSSL on " + str(url_with_port) + " (canceled tool 2/3)"); continue
                except Exception as e: print("Module SSL/TLS failed on TESTSSL stage (tool 2/3). Error: " + str(e)); continue
                print("Module SSL/TLS finished running TESTSSL on " + str(url_with_port) + " (tool 2/3) -> Elapsed time: " + format_seconds_to_mmss((datetime.now()-startTime).total_seconds()))
            if i == 2:
                startTime = datetime.now()
                try: sp = subprocess.run(['sslyze', '--reneg', '--robot', '--sslv2', '--sslv3', str(url_with_port)], capture_output=True, timeout=setTimeout)
                except subprocess.TimeoutExpired: print("Module SSL/TLS timed out ("+str(setTimeout)+"s) when running SSLYZE on " + str(url_with_port) + " (canceled tool 3/3)"); continue
                except Exception as e: print("Module SSL/TLS failed on SSLYZE stage (tool 3/3). Error: " + str(e)); continue
                print("Module SSL/TLS finished running SSLYZE on " + str(url_with_port) + " (tool 3/3) -> Elapsed time: " + format_seconds_to_mmss((datetime.now()-startTime).total_seconds()))
            # Grab the data...
            data = sp.stdout.decode()
            listData[i] = data # listData[0] = SSLSCAN-DATA, listData[1] = TESTSSL-DATA, listData[2] = SSLYZE-DATA
        if False: # For testing purposes (read file without performing scan -> Make this "True" and the previous one "False")
            if i in [1, 2]: continue
            with open("/mnt/hgfs/VM-Orchestrator-Debian/TestSSLSCAN.txt", "r") as f: data = f.read()
        
        if not data: continue # Just in case...
        runCipherParsing(scan_info, url_with_port, data)

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
        if "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED" in listAllVulnsFound: observation += "** ADH/ECDH ciphers enabled (allowing anonymous authentication).\n"
        observation += "\n"
    if "TLS_POODLE_VULNERABILITY" in listAllVulnsFound: observation += "* TLS vulnerable to POODLE attack.\n\n"
    if "PERFECT_FORWARD_SECRECY_DISABLED" in listAllVulnsFound: observation += "* Perfect Forward Secrecy not supported / Inadequate Perfect Forward Secrecy support (DH enabled cipher-suites are not preferred).\n\n"
    if "SSL2_DROWN_ATACK" in listAllVulnsFound: observation += "* DROWN attack vulnerability (CVE-2016-0800).\n\n"
    # Implication...
    if "SSL_VERSION_2_ENABLED" in listAllVulnsFound or "SSL_VERSION_3_ENABLED" in listAllVulnsFound:
        if "it-has-CBC-ciphers-in-SSLv2-3" in list_notes: implication += "* Security issues in the SSLv2 and SSLv3 protocols may allow a malicious individual to perform man-in-the-middle attacks. By forcing communication to a less secure level and then attempting to break the weak encryption, it may provide an opportunity to gain unauthorized access to data in transmission.\nFor reference, please see the following link: https://www.openssl.org/~bodo/ssl-poodle.pdf.\n"
        else:                                             implication += "* Security issues in the SSLv2 and SSLv3 protocols may allow a malicious individual to perform man-in-the-middle attacks. By forcing communication to a less secure level and then attempting to break the weak encryption, it may provide an opportunity to gain unauthorized access to data in transmission.\n"
    if "TLS_VERSION_1.0_ENABLED" in listAllVulnsFound or "TLS_VERSION_1.1_ENABLED" in listAllVulnsFound: implication += "* Security issues in the TLSv1.1 and earlier protocols may allow a malicious individual, who perform a man-in-the-middle attack, to predict the initialization vector blocks used to mask data prior to encryption.\n"
    if "TLS_BIRTHDAY_ATTACK_POSSIBLE" in listAllVulnsFound: implication += "* Certain block ciphers, such as 3DES and Blowfish have a block size of 64 bits. When used in CBC mode, these ciphers are known to be susceptible to the birthday attack. A malicious individual may attempt to inject a malicious Javascript to generate traffic and capture it to recover data.\nFor reference, please see the following link: https://sweet32.info/SWEET32_CCS16.pdf.\n"
    if "TLS_POODLE_VULNERABILITY" in listAllVulnsFound: implication += "* A TLS implementation which has been identified as vulnerable to POODLE may allow a malicious individual performing a man-in-the-middle attack against an application’s user, who is able to force this user’s browser to make multiple requests containing a specially crafted payload, to attempt an oracle-based attack on the communication, thus gaining unauthorized access to the data in transmission.\n"    
    if any(item in ["WEAK_ENCRYPTION_CYPHERS", "WEAK_ENCRYPTION_CYPHERS_RSA_EXPORT_FREAK","EDH_CIPHERS_DETECTED"] for item in listAllVulnsFound):
        implication += "* Weak RSA's/EDH’s (Less than 512 bits) and encryption’s key length algorithms (Less than 128 bits) may allow a malicious individual to decrypt the data stream via a brute force approach, by forcing communication to a less secure level and then attempting to break the weak encryption, in order to gain unauthorized access to data.\n"
    if "WEAK_ENCRYPTION_CYPHERS_RC4_CIPHERS" in listAllVulnsFound: implication += "* Security issues in the RC4 encryption algorithm that may allow a malicious individual to recover plaintext from a TLS connection.\nFor additional information, please refer to the following link: http://www.isg.rhul.ac.uk/tls/.\n"
    if "PERFECT_FORWARD_SECRECY_DISABLED" in listAllVulnsFound: implication += "* A malicious individual who manages to compromise the web server’s private key, would be able to leverage it in order to gain unauthorized access to sensitive information by breaking the encryption of previously intercepted communications.\n"
    if "SSL_TLS_WEAK_DIFFIE_HELLMAN_VULNERABILITY_LOGJAM" in listAllVulnsFound: implication += "* DHE cipher suites with 1024 bits or smaller primes may allow a malicious individual to attempt compromising the connection of sites sharing the same common prime numbers of the Diffie-Hellman key exchange.\n"
    if "SSL2_DROWN_ATACK" in listAllVulnsFound: implication += "* A strong TLS communication may be deciphered by a malicious individual performing a man-in-the-middle attack, if the affected host(s) share(s) the authentication RSA private key with another host that supports SSLv2 EXPORT-GRADE cipher-suites, by using the SSLv2 host as an RSA Padding Oracle.\nFor reference, please see the following link: https://drownattack.com/.\n"
    if "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED" in listAllVulnsFound: implication += "* SSL / TLS client-server communication may use several different types of authentication. Clients usually authenticate a server using an algorithm such as RSA or DSS. When clients are allowed to connect using no authentication, communications may be vulnerable to a man-in-the-middle attack. A malicious individual may leverage this in order to perform further attacks, such as impersonating the server and/or credential theft.\n"
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
    if "SSL_SERVER_ANONYMOUS_AUTHENTICATION_ALLOWED" in listAllVulnsFound: recommendation += "* Management should consider reviewing the requirement to support anonymous authentication for SSL / TLS configurations. If not required for business or functional purposes, they should be disabled (not support them). Most up-to-date browsers will default to the highest protocol and cipher. This will also ensure SSL / TLS related configurations are consistent with all web based applications within the organization.\n"
    # Strategic Recommendation...
    recommendation += "\nStrategic Recommendation:\n\n* Management should consider reviewing their system configuration standards to ensure that TLS configurations are in line with organizational policies and ensure that TLS related configurations are consistent with all Internet-facing applications within the organization.\nFor additional information, please refer to the following link: https://cwe.mitre.org/data/definitions/326.html.\n"

    # Ordeno para que se reporte primero SSLv2 -> SSLv3 -> TLSv1.0 -> TLSv1.1
    listFoundCipherVulnsTmp = []
    # Step 1/3 (Ordeno primero SSLv2 -> SSLv3 -> TLSv1.0 -> TLSv1.1 y las pongo en lista temporal)
    for i in range(4):
        for j in range(len(listFoundCipherVulns)):
            if (i == 0 and listFoundCipherVulns[j][3] == "SSL_VERSION_2_ENABLED") or \
                (i == 1 and listFoundCipherVulns[j][3] == "SSL_VERSION_3_ENABLED") or \
                    (i == 2 and listFoundCipherVulns[j][3] == "TLS_VERSION_1.0_ENABLED") or \
                        (i == 3 and listFoundCipherVulns[j][3] == "TLS_VERSION_1.1_ENABLED"):
                            listFoundCipherVulnsTmp.append(listFoundCipherVulns[j])
    # Step 2/3 (Relleno esa lista temporal luego con todos los demas issues)
    for i in range(len(listFoundCipherVulns)):
        if listFoundCipherVulns[i] not in listFoundCipherVulnsTmp:
            listFoundCipherVulnsTmp.append(listFoundCipherVulns[i])
    # Step 3/3 (Vuelvo a poner todo en la lista original)
    listFoundCipherVulns = listFoundCipherVulnsTmp
    
    # Ahora retorno todo lo encontrado en CIPHERS...    
    strMessage = "Cipher vulnerabilities were found.\n\n\n" + observation + "\n\n" + implication + "\n\n" + recommendation + "\n\n\n*Detection of issues:*\n\n"
    vulnsAlreadyReported = []
    img_str_list = [False, False, False] # It will be [SSLSCANboolean, TestSSLboolean, SSLYZEboolean] (Example: Only SSLSCAN -> [True, False, False])
    onlyPFS = True
    for i in range(len(listFoundCipherVulns)):
        if listFoundCipherVulns[i][4].lower() == "sslscan": img_str_list[0] = True
        if listFoundCipherVulns[i][4].lower() == "testssl": img_str_list[1] = True
        if listFoundCipherVulns[i][4].lower() == "sslyze":  img_str_list[2] = True
        if listFoundCipherVulns[i][3] != "PERFECT_FORWARD_SECRECY_DISABLED": onlyPFS = False
        if listFoundCipherVulns[i][3] in vulnsAlreadyReported: continue # Si ya se reporto un issue con SSLSCAN
        else: vulnsAlreadyReported.append(listFoundCipherVulns[i][3])   # no volver a reportarlo con TestSSL...
        strMessage += listFoundCipherVulns[i][2] + "\n\n"
    if listFoundCipherVulns and not onlyPFS: add_vulnerability(scan_info, strMessage, isCipherVuln=True, img_str_list=img_str_list, listData=listData)

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
    # Check connectors
    connectorsSmall = ["Furthermore, ", "In addition, ", "Finally, ", "Finally, ", "Finally, ", "Finally, "]
    cnt = 0
    if val and "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound:
        if "Not valid after: " in val: first = False; observation += "The certificate has been expired since " + str(val).replace("Not valid after: ", "").replace("The certificate is expired:", "").replace("\n", "").replace("> ", "").replace(">", "") + ". " + connectorsSmall[cnt]; cnt += 1
        elif "expired" in val and "--> " in val and ")" in val: first = False; observation += "The certificate has been expired since " + str(val[val.rfind("-->")+4:-1]).replace("Not valid after: ", "").replace("The certificate is expired:", "").replace("\n", "").replace("> ", "").replace(">", "") + ". " + connectorsSmall[cnt]; cnt += 1
    elif "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound:        first = False; observation += "The certificate has been expired since <Please check manually>. " + connectorsSmall[cnt]; cnt += 1
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound:
        if cnt > 0: observation += "The certificate has a weak RSA Key (less than 2048-bit key). " + connectorsSmall[cnt]; cnt += 1
        else:       observation += "its RSA Key is weak (less than 2048-bit key). " + connectorsSmall[cnt]; cnt += 1
    if "X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION" in listAllVulnsFound:
        if cnt > 0: observation += "The certificate was signed using a signature algorithm that is not secure. In particular, the affected target is using SHA1 based certificates. " + connectorsSmall[cnt]; cnt += 1
        else:       observation += "it was signed using a signature algorithm that is not secure. In particular, the affected target is using SHA1 based certificates. " + connectorsSmall[cnt]; cnt += 1
    elif "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION" in listAllVulnsFound:
        if cnt > 0: observation += "The certificate was signed using a signature algorithm that is not secure. In particular, the affected target is using MD5 based certificates. " + connectorsSmall[cnt]; cnt += 1
        else:       observation += "it was signed using a signature algorithm that is not secure. In particular, the affected target is using MD5 based certificates. " + connectorsSmall[cnt]; cnt += 1
    letterT = "t" if cnt > 0 else "T"
    if all(item in ["TLS_ROBOT_ATTACK", "TLS_RENEGOTIATION_VULNERABILITY"] for item in listAllVulnsFound): observation += letterT+"he target is vulnerable to the TLS ROBOT Attack and TLS Renegotiation vulnerabilities. " + connectorsSmall[cnt]; cnt += 1
    elif "TLS_ROBOT_ATTACK" in listAllVulnsFound: observation += letterT+"he target is vulnerable to the TLS ROBOT Attack vulnerability. " + connectorsSmall[cnt]; cnt += 1
    elif "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: observation += letterT+"he target is vulnerable to the TLS Renegotiation vulnerability. " + connectorsSmall[cnt]; cnt += 1
    observation = observation[:(-1)*len(str(connectorsSmall[cnt-1]))] # Remove last connector...
    # Implication...
    implication = "*Implication*:\n\nSSL / TLS certificates are a prime protection mechanism against phishing attacks. Web browsers are likely to display a warning message to the user, as authenticity cannot be guaranteed. Untrusted SSL / TLS certificates would continue to trigger the warning messages on the browser, which may lead to users becoming accustomed to the warnings and to start ignoring them. As a result, these users are more susceptible to threats, such as pharming and phishing or Man-in-the-Middle attacks. "
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound: implication += "Furthermore, its RSA weak keys don’t have enough randomness to withstand brute-force cracking attempts. "
    if "TLS_ROBOT_ATTACK" in listAllVulnsFound: implication += "Furthermore, the TLS ROBOT attack allows RSA decryption and signing operations to be performed using the server's private key. "
    if "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: implication += "Furthermore, The vulnerable renegotiation feature allows a malicious individual (who has successfully performed a man-in-the-middle attack) to send an arbitrary HTTP request to the server, with the aim of performing unintended actions on behalf of victims. "
    # Recommendation
    cnt = 0
    connectorsBig = ["Also, ", "Furthermore, ", "In addition, ", "Moreover, ", "Besides, ", "Also, " "Finally, ", "Finally, ", "Finally, ", "Finally, "]
    recommendation = "*Recommendation*:\n\nManagement should consider replacing the current untrusted SSL / TLS certificates on the servers, with valid and trusted certificates that are bound to a specific hostname and issued by a trusted certificate authority (CA). " + connectorsBig[cnt]; cnt += 1
    if "EXPIRED_SSL_CERTIFICATE" in listAllVulnsFound: recommendation += "management should consider reviewing their SSL / TLS certificate replacement policy and ensuring that renewal takes place prior to expiration dates. " + connectorsBig[cnt]; cnt += 1
    if any(item in ["X.509_CERTIFICATE_SHA1_SIGNATURE_COLLISION", "X.509_CERTIFICATE_MD5_SIGNATURE_COLLISION"] for item in listAllVulnsFound):
        recommendation += "management should consider reviewing their SSL / TLS certificate replacement policy and ensuring that renewal takes place using the SHA256 algorithm instead of SHA1. " + connectorsBig[cnt]; cnt += 1
    if "SERVER_PUBLIC_KEY_TOO_SMALL" in listAllVulnsFound: recommendation += "management should consider installing a server certificate signed with a public key length of at least 2048 bits. " + connectorsBig[cnt]; cnt += 1
    if "TLS_ROBOT_ATTACK" in listAllVulnsFound: recommendation += "it is recommended to apply vendor patches and fully disable the use of RSA for encryption to remediate the TLS Robot vulnerability. " + connectorsBig[cnt]; cnt += 1
    if "TLS_RENEGOTIATION_VULNERABILITY" in listAllVulnsFound: recommendation += "upgrading the identified affected software to the latest recommended version or apply all the relevant patches from the vendor relating to the insecure renegotiation issue. " + connectorsBig[cnt]; cnt += 1
    recommendation = "".join(recommendation.rsplit(connectorsBig[cnt-1], 1)) # connectorsBig[cnt-1] # Last connector used (it removes it)
    recommendation += "Finally, management should consider reviewing their SSL / TLS certificate policy, to ensure that SSL / TLS related configuration is consistent with all web based applications within the organization.\n\n"

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
    if listFoundCertificateVulns: add_vulnerability(scan_info, strMessage, isCertVuln=True, img_str_list=img_str_list, listData=listData)

    return
