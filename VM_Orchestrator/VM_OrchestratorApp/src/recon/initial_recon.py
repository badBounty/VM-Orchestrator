import VM_OrchestratorApp.src.utils.mongo as mongo

import subprocess
import os
from os import path
from datetime import datetime
import time
import requests
import json


def run_recon(scan_info):

    target_name = scan_info['target_name']

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/output'

    # Recon start notification
    #slack_sender.send_recon_start_message(target_name)

    if not path.exists(OUTPUT_DIR + '/' + target_name):
        os.makedirs(OUTPUT_DIR + '/' + target_name)

    PROJECT_DIR = OUTPUT_DIR + '/' + target_name

    # Commands
    amass_dir = ROOT_DIR + '/tools/amass'
    subfinder_dir = ROOT_DIR + '/tools/subfinder'
    sublist3r_dir = ROOT_DIR + "/tools/Sublist3r/sublist3r.py"

    # Amass
    print('------------------- AMASS STARTING -------------------')
    f = open(PROJECT_DIR + '/amass_out.txt',"w+")
    f.close()
    #amass_process = subprocess.run(
    #   [amass_dir, 'enum', '-active', '-d', target_name, '-o', PROJECT_DIR + '/amass_out.txt', '-timeout', '10'])
    if path.exists(PROJECT_DIR + '/amass_out.txt'):
        print('------------------- AMASS FINISHED CORRECTLY -------------------')

    # Subfinder
    print('------------------- SUBFINDER STARTING -------------------')
    subfinder_process = subprocess.run([subfinder_dir, '-d', target_name, '-o', PROJECT_DIR + '/subfinder_out.txt'])
    if path.exists(PROJECT_DIR + '/subfinder_out.txt'):
        print('------------------- SUBFINDER FINISHED CORRECTLY -------------------')

    # sublist3r
    print('------------------- SUBLIST3R STARTING -------------------')
    sublist3r_process = subprocess.run(
       ['python3', sublist3r_dir, '-d', target_name, '-o', PROJECT_DIR + '/sublist3r_out.txt'])
    if path.exists(PROJECT_DIR + '/sublist3r_out.txt'):
        print('------------------- SUBLIST3R FINISHED CORRECTLY -------------------')

    parse_results(PROJECT_DIR, scan_info)
    gather_data(PROJECT_DIR, scan_info)
    cleanup(PROJECT_DIR, OUTPUT_DIR)

    #slack_sender.send_recon_end_message(target_name)

    return


def parse_results(project_dir, scan_info):
    filenames = [project_dir + '/subfinder_out.txt', project_dir + '/sublist3r_out.txt', project_dir + '/amass_out.txt']
    with open(project_dir + '/all.txt', 'w') as outfile:
        for fname in filenames:
            with open(fname) as infile:
                outfile.write(infile.read())

    lines = open(project_dir + '/all.txt', 'r').readlines()
    lines = [line for line in lines if ('<' not in line or '>' not in line)]
    lines = [line.lower() for line in lines]
    lines = list(dict.fromkeys(lines))
    lines_set = set(lines)
    out = open(project_dir + '/all.txt', 'w')
    for line in lines_set:
        out.write(line)
    out.close()

    return


def gather_data(project_dir, scan_info):
    # Take final text file and run through API that checks information
    # Here we call the add_to_db
    timestamp = datetime.now()
    lines = open(project_dir + '/all.txt', 'r').readlines()

    for url in lines:
        url = url.replace('\n', '')
        try:
            is_alive = subprocess.check_output(['dig', url, '+short', '|', 'sed', "'/[a-z]/d'"])
        except subprocess.CalledProcessError:
            continue
        if is_alive.decode():
            is_alive_clause = 'True'
        else:
            is_alive_clause = 'False'
        try:
            has_ip = subprocess.check_output(['dig', url, '+short', '|', 'sed', "'/[a-z]/d'", '|', 'sed', '-n', 'lp'])
        except subprocess.CalledProcessError:
            continue

        url_info={
                'target_name': scan_info['target_name'],
                'url': url,
                'is_alive': is_alive_clause,
                'ip': None,
                'isp': None,
                'asn': None,
                'country': None,
                'region': None,
                'city': None,
                'org': None,
                'lat': None,
                'lon': None
        }
        if has_ip.decode():
            value = has_ip.decode().split('\n')
            ip = value[-2]
            url_info['ip'] = ip
            # If alive with IP, we try to find more information
            gather_additional_info(url_info, scan_info)
        else:
            # If not alive, we just add the info we have
            mongo.add_resource(url_info, scan_info)

    return


def gather_additional_info(url_info, scan_info):
    timestamp = datetime.now()
    response = requests.get('http://ip-api.com/json/' + url_info['ip'], verify=False)
    response_json = response.content.decode().replace('as', 'asn')
    try:
        parsed_json = json.loads(response_json)
    except Exception:
        mongo.add_resource(url_info, scan_info)
        return
    try:
        url_info['isp'] = parsed_json['isp']
        url_info['asn'] = parsed_json['asn']
        url_info['country'] = parsed_json['country']
        url_info['region'] = parsed_json['region']
        url_info['city'] = parsed_json['city']
        url_info['org'] = parsed_json['org']
        url_info['lat'] = parsed_json['lat']
        url_info['lon'] = parsed_json['lon']
        mongo.add_resource(url_info, scan_info)
    except KeyError:
        mongo.add_resource(url_info, scan_info)
        time.sleep(1)
        return
    time.sleep(1)
    return
    

def cleanup(PROJECT_DIR, OUTPUT_DIR):
    try:
        os.remove(PROJECT_DIR + '/all.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/amass_out.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/subfinder_out.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/sublist3r_out.txt')
    except FileNotFoundError:
        pass