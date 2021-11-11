#!/usr/bin/env python3
"""
###############################################################################
# check_cisco_cpuload.py
# Icinga/Nagios plugin that checks the cpu load on a Cisco Switch/Router via
# SNMPv3 using the CISCO-PROCESS-MIB
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
from pysnmp.hlapi import bulkCmd, SnmpEngine, UsmUserData, \
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
                 description="Icinga/Nagios plugin which checks cpu \
                              load on Cisco switches/routers",
                 epilog=""
             )
    parser.add_argument("-H", "--host", required=True,
                        help="hostname or IP address", type=str, dest='host')
    parser.add_argument("-p", "--port", required=False,
                        help="SNMP port", type=int, dest='port', default=161)
    parser.add_argument("-t", "--timeout", required=False,
                        help="SNMP timeout", type=int, dest='timeout',
                        default=10)
    parser.add_argument("-u", "--user", required=True,
                        help="SNMPv3 user name", type=str, dest='user')
    parser.add_argument("-l", "--seclevel", required=False,
                        help="SNMPv3 security level", type=str,
                        dest="v3mode",
                        choices=["authPriv", "authNoPriv"], default="authPriv")
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
                        help="warning thresholds (5sec,1min,5min)",
                        type=str, dest='warn', default="90,80,70")
    parser.add_argument("-c", "--crit", required=False,
                        help="warning thresholds (5sec,1min,5min)",
                        type=str, dest='crit', default="95,90,80")
    parser.add_argument("--mode", required=False, help="", type=str,
                        dest='mode',
                        default="CISCO-PROCESS-MIB_NEW",
                        choices=['CISCO-PROCESS-MIB_NEW',
                                 'CISCO-PROCESS-MIB_OLD'])
    args = parser.parse_args()
    return args


def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    if args.v3mode == "authPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey, args.privkey,
                        authProtocol=authprot[args.authmode],
                        privProtocol=privprot[args.privmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )
    elif args.v3mode == "authNoPriv":
        iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey,
                        authProtocol=authprot[args.authmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            0, 20,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False,
            lookupMib=False
        )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            exit_plugin("3", ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print(f"{error_status.prettyPrint()} at "
                  f"{error_index and var_binds[int(error_index) - 1][0] or '?'}")
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

    # divide thresholds into individual vars and make type conversion
    w5sec, w1min, w5min = map(int, args.warn.split(","))
    c5sec, c1min, c5min = map(int, args.crit.split(","))

    if args.mode == "CISCO-PROCESS-MIB_NEW":
        # Use revised OIDs in CISCO-PROCESS-MIB
        #     CISCO-PROCESS-MIB::cpmCPUTotal5secRev
        #     CISCO-PROCESS-MIB::cpmCPUTotal1minRev
        #     CISCO-PROCESS-MIB::cpmCPUTotal5minRev
        l5sec = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.6', args)
        l1min = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.7', args)
        l5min = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.8', args)

    if args.mode == "CISCO-PROCESS-MIB_OLD":
        # Use deprecated OIDs in CISCO-PROCESS-MIB
        #     CISCO-PROCESS-MIB::cpmCPUTotal5sec
        #     CISCO-PROCESS-MIB::cpmCPUTotal1min
        #     CISCO-PROCESS-MIB::cpmCPUTotal5min
        l5sec = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.3', args)
        l1min = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.4', args)
        l5min = get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.5', args)

    if len(l5sec) == 0 or len(l1min) == 0 or len(l5min) == 0:
        # Check if we received data via SNMP, otherwise exit with state Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    # Extract OID identifier from OID
    for entry in chain(l5sec, l1min, l5min):
        entry[0] = entry[0].strip().split(".")[-1:]
        entry[0] = "".join(map(str, entry[0]))
        entry[1] = entry[1].strip()

    # Create list with CPU identifiers
    cpuids = []
    for i in l5sec:
        cpuids.append(i[0])

    # Set return code and generate output and perfdata strings
    returncode = "0"
    perfdata = ""
    output = ""

    for i in cpuids:
        # loop through CPU id's
        cpuid = i

        for entry in l5sec:
            # loop throug 5sec values and extract reading for this CPU ID
            if str(entry[0]) == str(cpuid):
                val5sec = float(entry[1])

        for entry in l1min:
            # loop throug 5sec values and extract reading for this CPU ID
            if str(entry[0]) == str(cpuid):
                val1min = float(entry[1])

        for entry in l5sec:
            # loop throug 5sec values and extract reading for this CPU ID
            if str(entry[0]) == str(cpuid):
                val5min = float(entry[1])

        # Append to perfdata and output string
        perfdata += ''.join(["\'cpuload_5sec_", str(cpuid), "\'=",
                             str(val5sec), "%;", str(w5sec), ";",
                             str(c5sec), ";0;100 ", "\'cpuload_1min_",
                             str(cpuid), "\'=", str(val1min), "%;", str(w1min),
                             ";", str(c1min), ";0;100 ", "\'cpuload_5min_",
                             str(cpuid), "\'=", str(val5min), "%;", str(w5min),
                             ";", str(c5min), ";0;100 "])

        output += ''.join(["CPU ", str(cpuid), ": (5s: ", str(val5sec),
                           "%, 1m: ", str(val1min), "%, 5m: ", str(val5min),
                           "%), "])

        # Evaluate against thresholds
        if (val5sec >= c5sec) or (val1min >= c1min) or (val5min >= c5min):
            returncode = "2"
        if returncode != "2" and ((val5sec >= w5sec) or (val1min >= w1min) or
                                  (val5min >= w5min)):
            returncode = "1"

    # Remove last comma from output string
    output = output.rstrip(', ')

    exit_plugin(returncode, output, perfdata)


if __name__ == "__main__":
    main()
