import os

def start_httprobe(subdomain_list, scan_info):
    print('Starting httprobe against ' + str(len(subdomain_list))+ ' subdomains')
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/httprobe'
    OUTPUT_DIR = ROOT_DIR + '/output'
    for subdomain in subdomain_list:
        print('Probing %s' % subdomain['subdomain'])
        with open(OUTPUT_DIR+'/httprobe_input.txt', 'w') as f:
            f.write("%s\n" % subdomain['subdomain'])

        output = os.popen('cat httprobe_input.txt | '+TOOL_DIR).read()
        output_list = output.split('\n')
        output_list.remove("")
        for item in output_list:
            print(item)

        try:
            os.remove(OUTPUT_DIR+'/httprobe_input.txt')
        except OSError:
            pass


    return