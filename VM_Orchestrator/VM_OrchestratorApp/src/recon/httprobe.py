import os

def start_httprobe(subdomain_list, scan_info):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/httprobe'
    OUTPUT_DIR = ROOT_DIR + '/output'

    with open(OUTPUT_DIR+'httprobe_input.txt', 'w') as f:
        for item in subdomain_list:
            f.write("%s\n" % item['subdomain'])

    output = os.popen('cat httprobe_input.txt | '+TOOL_DIR).read()
    output_list = output.split('\n')
    output_list.remove("")
    for item in output_list:
        print(item)


    return