"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import re
import os
import pandas

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 10, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """

    captured_data = []
    dpt_records = {}

    # TODO: Complete function body per step 8
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search('DPT=(.+?) ', record)
            if match:
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())
    for dpt_record in captured_data:
        dpt_no = dpt_record[0]
        dpt_records[dpt_no]=dpt_records.get(dpt_no,0)+1
    return dpt_records

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Complete function body per step 9
    list = []

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            str = 'DPT='+port_number
            match = re.search(str, record)
            if match:
                date = re.findall('\S+\s+\d{2}', record)
                time = re.findall('\d{2}:\d{2}:\d{2}', record)
                src_data = re.findall('SRC=(.*?) ', record)
                dst_data = re.findall('DST=(.*?) ', record)
                src_prt = re.findall('SPT=(.*?) ', record)
                dst_prt = re.findall('DPT=(.*?) ', record)

                if len(src_data) == 1:
                    data_tupl = (date[0],time[0],src_data[0],dst_data[0],src_prt[0],dst_prt[0])
                    list.append(data_tupl)

    report_df = pandas.DataFrame(list)
    report_header=('Date','Time','Source IP Address','Destination IP address','Source Port','Destination Port')
    report_df.to_csv(f"destination_port_{port_number}_report.csv",index=False,header=report_header)
    return

    # Generate the CSV report

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 11
    list=[]
    # Get data from records that show attempted invalid user login
    with open(log_path,'r') as file:
        for record in file:
            match=re.search('Invalid user ',record)
            if match:
                date = re.findall('(\S+\s+\d{2}) \d{2}:', record)
                time = re.findall('\d{2}:\d{2}:\d{2}', record)
                user = re.findall('Invalid user (\S+) from', record)
                ip_addr = re.findall('from (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', record)
                if len(date) == 1:
                    data_tupl = (date[0],time[0],user[0],ip_addr[0])
                    list.append(data_tupl)

    # Generate the CSV report
    report_df = pandas.DataFrame(list)
    report_header = ('Date', 'Time', 'Username', 'IP Address')
    report_df.to_csv('invalid_users.csv', index=False, header=report_header)
    return


def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 12

    filtered_records = []
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            matchcase = 'SRC=' + ip_address
            match = re.search(matchcase, record)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
    report_df = pandas.DataFrame(filtered_records)
    new_ip = re.sub('\.', '_', ip_address)
    report_df.to_csv(f"source_ip_{new_ip}.log", index=False,header=None)
    # Get all records that have the specified sourec IP address
    # Save all records to a plain text .log file
    return

if __name__ == '__main__':
    main()