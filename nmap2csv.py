#!/usr/bin/python
"""Parse nmap xml file(s) and write csv output to a file or stdout"""

################################################################################
# nmap2csv.py
#
# v1.0   16/03/2017 - Josep Fontana - Initial Python rewrite of namp2csv.pl
#


################################################################################
# imports
################################################################################

import sys
import xml.etree.cElementTree as etree
import argparse
import re
import glob
import csv


################################################################################
# ARGUMENT PARSING functions
################################################################################

# parse input arguments
# return
# TODO: check that output != input, input is *.xml
# TODO: check that output exists and does not contain wildcards (os.path.isfile())
def parse_args():
    """Parse input arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='nmap XML file to be parsed, this argument is required')
    parser.add_argument('-o', '--output', help='csv file to write the output, default is stdout')
    args = parser.parse_args()

    # treat wildcards
    files = glob.glob(args.input)
    if not files:
        sys.stderr.write(' *** ERROR: the file "' +
                         args.input +
                         '" does not exist or cannot be read\n')
        exit(1)

    return files, args.output
    # return ['unops_public_top2000_sSCV.xml'], args.output


################################################################################
# XML PARSE functions
################################################################################

def host_address(host):
    """Get the host IP address.

    Returns the IP address as a string
    host: etree element for a host node
    """

    try:
        return host.find('address').get('addr')
    except:
        sys.stderr.write(' *** ERROR: the host with starttime "' +
                         str(host.get('starttime')) +
                         '" does not have an address !!!\n')
        return None


def host_status(host):
    """Get the host status.

    Returns the status string, defaults to 'unknown'
    host: etree element for a host node
    """

    try:
        return host.find('status').get('state')
    except:
        sys.stderr.write(' *** ERROR: the host with starttime "' +
                         str(host.get('starttime')) +
                         '" does not have a status !!!\n')
        return 'unknown'


def host_name(host):
    """Get the hostname of a host. Does not treat the multiple hostnames case.

    Returns the hostname string, defaults to 'N/A'
    host: etree element for a host node
    """

    # TODO: multiple hostnames
    try:
        return host.find('hostnames').find('hostname').get('name')
    except:
        # the host does not have a hostname
        return 'N/A'


def host_os(host):
    """Get the operating system reported by 'nmap -O'.

    Returns the OS string, defaults to 'N/A'
    host: etree element for a host node
    """

    try:
        return host.find('os').find('osmatch').get('name')
    except:
        # not really an error, it's just that the os was not guessed
        return 'N/A'


def host_os_smb(host):
    """Get the OS from the 'smb-os-discovery' nmap script output

    Returns the OS from the 'smb-os-discovery' script, defaults to 'N/A
    host: etree element for a host node
    """

    try:
        # iterate through all host scripts
        for script in host.find('hostscript').findall('script'):
            if script.get('id') == 'smb-os-discovery':
                # get the OS name among other results
                for result in script.findall('elem'):
                    if result.get('key') == 'os':
                        return result.text
                break
    except:
        # not really an error, again
        return 'N/A'


def host_location(ip):
    """TODO: GET the host location based on its IP address, and using an external file.

    Returns the location of a host given its IP address, by looking in an external file
    that contains known IP ranges.
    ip: ip address of the host
    """

    return 'N/A'


def host_ports(host):
    """Get the open port(s) of a host, and return them as a list.

    Returns a dictionary of found ports for a given host. Each element has the port name as a key
    (in the same notation as used in the ports global variable)
    and a text with the maximum information available (product, version, port and protocol)
    host: etree element for a host node
    """

    if host.find('ports') is None:
        found_ports = None
    else:
        found_ports = dict()
        for port in host.find('ports').findall('port'):
            # make sure that the port is open
            try:
                if port.find('state').get('state') != 'open':
                    continue
            except:
                # the port has no state !!!
                continue

            # get the port, append protocol if not tcp
            if port.get('protocol') == 'tcp':
                port_id = port.get('portid')
            else:
                port_id = port.get('portid') + '/' + port.get('protocol')

            # get the service name
            try:
                service = port.find('service').get('name')
            except:
                service = ''

            # build the port/service index
            p_index = port_id + ' (' + service + ')'

            # get the product name and version - if the service scan was done
            try:
                srv_prod = port.find('service').get('product')
                srv_prod = srv_prod.replace(",", "").replace('\n', ' ').replace('\r', '')
            except:
                srv_prod = None
            try:
                srv_ver = port.find('service').get('version')
                srv_ver = srv_ver.replace(",", "").replace('\n', ' ').replace('\r', '')
            except:
                srv_ver = None

            # build the text to include in the csv for an open port
            if srv_prod is None:
                found_service = port_id
            elif srv_ver is None:
                found_service = srv_prod
            else:
                found_service = srv_prod + ' (' + srv_ver + ')'

            # add the port to the host ultra-nested dictionary
            found_ports[p_index] = found_service

    return found_ports


def atoi(text):
    """Taken from http://nedbatchelder.com/blog/200712/human_sorting.html"""
    return int(text) if text.isdigit() else text


def natural_keys(text):
    """Human sort algorith taken from http://nedbatchelder.com/blog/200712/human_sorting.html

    Returns the input list sorted in human order
    text: list to be sorted
    """
    return [atoi(c) for c in re.split('(\d+)', text)]


def add_to_big_list(big_list, new_items):
    """
    Adds new items to a big list (NOT dictionaries).

    Returns the big list with the new items appended to the end, without repetitions
    big_list: list to be extended
    new_items: list of new items to include in the big_list
    """

    # check if we really have new items
    if new_items is None:
        return big_list

    # make sure that new_items is a list
    if not isinstance(new_items, list):
        new_items = [new_items]

    # add the items to the big list if not yet there
    for item in new_items:
        if item not in big_list:
            big_list.append(item)

    # return the (un!)sorted big list
    return big_list


def parse_host(host, hosts, ports, hs_ps):
    """
    Parse a host node of the xml and add the extracted information to hosts, ports and hs_ps.

    Returns nothing
    host: etree element containing the information for one host
    hosts: ordered list of scanned hosts, will be extended by this function
    ports: ordered list of ports that are open on at least one host,
           will be extended by this function
    hs_ps: nested dictionary using hosts and ports as keys, will be extended by this function
    """

    # get this host's ip, will use it as a reference
    ip = host_address(host)
    # add this host to the list of scanned hosts
    hosts = add_to_big_list(hosts, ip)

    # create the nested dictionary for this host
    # TODO: refactor so the full hs_ps doesn't need to go out of parse_file
    hs_ps[ip] = dict()

    # populate it with stuff
    hs_ps[ip]['status'] = host_status(host)
    hs_ps[ip]['hostname'] = host_name(host)
    hs_ps[ip]['os'] = host_os(host)
    hs_ps[ip]['os-smb'] = host_os_smb(host)
    # TODO: SMB-SQL column
    # TODO: HTTP-Title column
    hs_ps[ip]['location'] = host_location(ip)
    hs_ps[ip]['ports'] = host_ports(host)

    # add this host's open ports to the global list of ports
    try:
        ports = add_to_big_list(ports, hs_ps[ip]['ports'].keys())
    except AttributeError:
        # hs_ps[ip]['ports'] is None, nothing to do here
        return


def parse_file(filename, hosts, ports, hs_ps):
    """Parse a file and add the hosts and ports information to hosts, ports and hs_ps.

    Returns nothing
    filename: nmap-generated xml file to be parsed
    hosts: ordered list of scanned hosts, will be extended by this function
    ports: ordered list of ports that are open on at least one host,
           will be extended by this function
    hs_ps: nested dictionary using hosts and ports as keys, will be extended by this function
    """
    # load the xml file and get the root element
    tree = etree.parse(filename)
    #tree = etree.parse('bi.xml')
    root = tree.getroot()
    for host in root:
        # check if this is a host, if not continue to next element
        if host.tag == 'host':
            parse_host(host, hosts, ports, hs_ps)


################################################################################
# OUTPUT functions
################################################################################

def out_header(ports):
    """Generates the output header.

    Returns that line as a list.
    ports: ordered list of ports that are open on at least one host
    """

    header = ['Hostname', 'IP', 'OS', 'SMB-OS', 'Location', 'Status']
    header.extend(ports)
    return header

def out_hostline(ip, host, ports):
    """Generates an output line list per host.

    Returns that line list
    ip: string with the ip address of the host
    host: dictionary using ports as key
    ports: ordered list of ports that are open on at least one host
    """

    # line = [h['hostname'],',',host,',',h['os'],',',h['os-smb'],',',h['location'],',',h['status'],
    line = [host['hostname'], ip, host['os'], host['os-smb'], host['location'], host['status']]

    #,',',','.join(str(i) for i in h['ports']), h['ports']
    # it is showing the keys, but we want the values for each of the ports list items
    for i in xrange(len(ports)):
        try:
            line.append(host['ports'][ports[i]])
        except:
            line.append('')

    return line


def print_output(output, hosts, ports, hs_ps):
    """Print output either to a csv file or the stdout.

    Returns nothing.
    output: csv file name or False if we should write to stdout
    hosts: ordered list of scanned hosts
    ports: ordered list of ports that are open on at least one host
    hs_ps: nested dictionary using hosts and ports as keys
    """

    if output:
        # open the output file
        try:
            fout = open(output, 'w')
        except IOError:
            sys.stderr.write(' *** ERROR: the file "' +
                             output +
                             '" cannot be created/overwritten !!!\n')
            exit(1)
    else:
    # if the output file is not provided, use standard output
        fout = sys.stdout

    # create csv writer object
    csv_out = csv.writer(fout, dialect='excel')
    # write header
    csv_out.writerow(out_header(ports))
    # write all the lines, hosts is a list of IP
    for host in hosts:
        csv_out.writerow(out_hostline(host, hs_ps[host], ports))


################################################################################
# MAIN
################################################################################

def main():
    """Main function"""

    # list of hosts that were scanned
    hosts = []
    # list of all ports found open in any host
    ports = []
    # nested dictionary with
    # it will be read using hosts[] and ports[]
    hs_ps = dict()

    # parse arguments
    files, output = parse_args()
    # parse file(s)
    for fxml in files:
        parse_file(fxml, hosts, ports, hs_ps)

    # sort the hosts and ports lists
    hosts.sort(key=natural_keys)
    ports.sort(key=natural_keys)

    # print output
    print_output(output, hosts, ports, hs_ps)
    # done!

if __name__ == '__main__':
    main()

# TODO: remove profile code
#import profile
#profile.run('main()')
