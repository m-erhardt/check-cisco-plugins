#!/bin/env python3.6
"""
###############################################################################
# check_cisco_memusage.py
# Nagios plugin that checks the system memory usage on a Cisco Switch/Router
# via SNMPv3 using the CISCO-PROCESS-MIB
#
#
# Author        : Mauno Erhardt <mauno.erhardt@burkert.com>
# Copyright     : (c) 2021 Burkert Fluid Control Systems
# Source        : https://github.com/m-erhardt/check-cisco-plugins
# License       : GPLv3 (http://www.gnu.org/licenses/gpl-3.0.txt)
#
###############################################################################
"""

import sys
from argparse import ArgumentParser
from itertools import chain
from pysnmp.hlapi import nextCmd, SnmpEngine, UsmUserData, \
                         UdpTransportTarget, \
                         ObjectType, ObjectIdentity, \
                         ContextData, usmHMACMD5AuthProtocol, \
                         usmHMACSHAAuthProtocol, \
                         usmHMAC128SHA224AuthProtocol, \
                         usmHMAC192SHA256AuthProtocol, \
                         usmHMAC256SHA384AuthProtocol, \
                         usmHMAC384SHA512AuthProtocol, usmDESPrivProtocol, \
                         usm3DESEDEPrivProtocol, usmAesCfb128Protocol, \
                         usmAesCfb192Protocol, usmAesCfb256Protocol

authprot = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
    }
privprot = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}


def get_args():
    """ Parse Arguments """
    parser = ArgumentParser(
                 description="Icinga/Nagios plugin which checks system memory \
                             usage on Cisco switches/routers",
                 epilog=""
             )
    parser.add_argument("-H", "--host", required=True,
                        help="hostname or IP address", type=str, dest='host')
    parser.add_argument("-p", "--port", required=False, help="SNMP port",
                        type=int, dest='port', default=161)
    parser.add_argument("-t", "--timeout", required=False,
                        help="SNMP timeout", type=int, dest='timeout',
                        default=10)
    parser.add_argument("-u", "--user", required=True,
                        help="SNMPv3 user name", type=str, dest='user')
    parser.add_argument("-A", "--authkey", required=True,
                        help="SNMPv3 auth key", type=str, dest='authkey')
    parser.add_argument("-X", "--privkey", required=True,
                        help="SNMPv3 priv key", type=str, dest='privkey')
    parser.add_argument("-a", "--authmode", required=False,
                        help="SNMPv3 auth mode", type=str, dest='authmode',
                        default='SHA',
                        choices=['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384',
                                 'SHA512'])
    parser.add_argument("-x", "--privmode", required=False,
                        help="SNMPv3 privacy mode", type=str, dest='privmode',
                        default='AES',
                        choices=['DES', '3DES', 'AES', 'AES192', 'AES256'])
    parser.add_argument("-w", "--warn", required=False,
                        help="warning threshold (in percent)",
                        type=float, dest='warn', default="70")
    parser.add_argument("-c", "--crit", required=False,
                        help="warning thresholds (in percent)",
                        type=float, dest='crit', default="80")
    parser.add_argument("--mib", required=False, help="use OIDs from this MIB",
                        type=str, dest='mib',
                        default="CISCO-PROCESS-MIB",
                        choices=["CISCO-PROCESS-MIB", "CISCO-MEMORY-POOL-MIB"])
    args = parser.parse_args()
    return args


def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    iterator = nextCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey, args.privkey,
                        authProtocol=authprot[args.authmode],
                        privProtocol=privprot[args.privmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
    )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            print(error_indication)
        elif error_status:
            print('%s at %s' % (error_status.prettyPrint(),
                                error_index and
                                var_binds[int(error_index) - 1][0] or '?'))
        else:
            # split OID and value into two fields and append to return element
            table.append([str(var_binds[0][0]), str(var_binds[0][1])])

    # return list with all OIDs/values from snmp table
    return table


def exit_plugin(returncode, output, perfdata):
    """ Check status and exit accordingly """
    if returncode == "3":
        print("UNKNOWN - " + str(output))
        sys.exit(3)
    if returncode == "2":
        print("CRITICAL - " + str(output) + " | " + str(perfdata))
        sys.exit(2)
    if returncode == "1":
        print("WARNING - " + str(output) + " | " + str(perfdata))
        sys.exit(1)
    elif returncode == "0":
        print("OK - " + str(output) + " | " + str(perfdata))
        sys.exit(0)


def main():
    """ Main program code """

    # Get Arguments
    args = get_args()

    if args.mib == "CISCO-PROCESS-MIB":
        # Use revised OIDs in CISCO-PROCESS-MIB
        #     CISCO-PROCESS-MIB::cpmCPUMemoryUsed
        #     CISCO-PROCESS-MIB::cpmCPUMemoryFree
        mem_used = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.12', args)
        mem_free = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.13', args)

    if args.mib == "CISCO-MEMORY-POOL-MIB":
        # Use OIDs in CISCO-MEMORY-POOL-MIB
        #     CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolUsed
        #     CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolFree
        mem_used = get_snmp_table('1.3.6.1.4.1.9.9.48.1.1.1.5', args)
        mem_free = get_snmp_table('1.3.6.1.4.1.9.9.48.1.1.1.6', args)

    if len(mem_used) == 0 or len(mem_free) == 0:
        # Check if we received data via SNMP, otherwise exit with state Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    # Extract OID identifier from OID
    for entry in chain(mem_used, mem_free):
        entry[0] = entry[0].strip().split(".")[-1:]
        entry[0] = "".join(map(str, entry[0]))
        entry[1] = entry[1].strip()

    # Create list with CPU identifiers
    memids = []
    for i in mem_free:
        memids.append(i[0])

    if args.mib == "CISCO-MEMORY-POOL-MIB":
        # Further changes for CISCO-MEMORY-POOL-MIB

        # CISCO-MEMORY-POOL-MIB gives readings in B instead of KB,
        # convert accordingly
        for i in mem_used:
            i[1] = round(int(i[1]) / 1024, 2)
        for i in mem_free:
            i[1] = round(int(i[1]) / 1024, 2)

    # Set return code and generate output and perfdata strings
    returncode = "0"
    perfdata = ""
    output = ""

    for i in memids:
        # loop through memory id's
        memid = i

        for entry in mem_used:
            # loop through "mempory used" values and extract reading
            # for this memory ID
            if str(entry[0]) == str(memid):
                used = float(entry[1])

        for entry in mem_free:
            # loop throug "memory free" values and extract reading for this
            # CPU ID
            if str(entry[0]) == str(memid):
                free = float(entry[1])

        # Calculate total memory and thresholds (all in KB)
        total = free + used
        warn_b = round(total * (args.warn / 100))
        crit_b = round(total * (args.crit / 100))

        # Calculate percentages
        used_pct = round((used / total) * 100, 2)

        # Append to perfdata and output string
        perfdata += ''.join(["\'mem_used_", str(memid), "\'=", str(used),
                             "KB;", str(warn_b), ";", str(crit_b), ";0;",
                             str(total), " "])
        output += ''.join(["Memory (", str(memid), "): ", str(used_pct),
                           "%, "])

        # Evaluate against thresholds
        if used >= crit_b:
            returncode = "2"
        if returncode != "2" and used >= warn_b:
            returncode = "1"

    # Remove last comma from output string
    output = output.rstrip(', ')

    exit_plugin(returncode, output, perfdata)

if __name__ == "__main__":
    main()
