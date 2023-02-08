from sys import argv, exit
import os
import re
import pandas as pd
from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
def main():
    log_file = get_log_file_path_from_cmd_line(1)
    port_traffic = tally_port_traffic(log_file)
    generate_port_traffic_report(log_file, 40686)
    for port_num, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port_num)
    
    pass





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

    
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):

    #item 0 instead of 1 when running filter_log_by_regex
    #header=None plain text file?
    return

if __name__ == '__main__':
    main()