import os

def start_httprobe(subdomain_list, scan_info):
    print('Starting httprobe against ' + str(len(subdomain_list))+ ' subdomains')
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/httprobe'
    OUTPUT_DIR = ROOT_DIR + '/output/httprobe_input.txt'
    for subdomain in subdomain_list:
        print('Probing %s' % subdomain['subdomain'])
        with open(OUTPUT_DIR, 'w') as f:
            f.write("%s\n" % subdomain['subdomain'])

        output = os.popen('cat ' + OUTPUT_DIR + ' | '+TOOL_DIR).read()
        print(output)
        output_list = output.split('\n')
        output_list.remove("")
        for item in output_list:
            print(item)

        try:
            os.remove(OUTPUT_DIR)
        except OSError:
            pass


    return