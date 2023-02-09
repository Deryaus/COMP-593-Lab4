import pandas as pd
from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import re
import numpy as np

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    port_traffic = tally_port_traffic(log_file)
    generate_port_traffic_report(log_file, 40686)
    for port_num, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port_num)
    generate_invalid_user_report(log_file)
    generate_source_ip_log(log_file, '220.195.35.40')
     
def tally_port_traffic(log_file):
    data = filter_log_by_regex(log_file, r'DPT=(.+?) ')[1]
    port_traffic = {}
    for d in data:
        port = d[0]
        port_traffic[port] = port_traffic.get(port, 0) +1
    return port_traffic

def generate_port_traffic_report(log_file, port_number):
    regex = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.+?) .+SPT=(.+)' + f'DPT=({port_number})'
    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)
    header_row = ('Date', 'Time', 'Source IP Address', 'Destination IP address', 'Source Port', 'Destination Port')
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=header_row)

def generate_invalid_user_report(log_file):
    regex = r'(.{6}) (.{8}) .* Invalid user (.+?) .*(\d{3}.\d{3}.\d+.\d+)'
    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)
    header_row = ('Date', 'Time', 'Username', 'IP Address')
    report_df.to_csv('Invalid_users.csv', index=False, header=header_row,)
    
# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    regex = f'.* SRC={ip_address} .*'
    address = re.sub('\.', '_', ip_address)
    data = filter_log_by_regex(log_file, regex)[0]
    report_df = pd.DataFrame(data)
    report_df.to_csv(f'source_ip_{address}.log', index=False, header=False,  escapechar=' ', lineterminator=' ')
    #quotechar=' ' mode='w' , sep=' ' 
    #with open(f'source_ip_{address}.log', 'w') as f: 
        #f.write(report_df.to_string(header=False, index=False))

if __name__ == '__main__':
    main()