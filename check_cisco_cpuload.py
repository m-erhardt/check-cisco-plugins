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
import asyncio
from argparse import ArgumentParser
from itertools import chain
from pysnmp.hlapi.v3arch.asyncio import bulk_walk_cmd, SnmpEngine, UsmUserData, \
                         UdpTransportTarget, Udp6TransportTarget, \
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
                              load on Cisco switches/routers")

    checkopts = parser.add_argument_group('Check parameters')
    checkopts.add_argument("--mode", required=False, help="", type=str,
                           dest='mode',
                           default="CISCO-PROCESS-MIB_NEW",
                           choices=['CISCO-PROCESS-MIB_NEW',
                                    'CISCO-PROCESS-MIB_OLD'])

    thresholds = parser.add_argument_group('Thresholds')
    thresholds.add_argument("-w", "--warn", required=False,
                            help="warning thresholds (5sec,1min,5min)",
                            type=str, dest='warn', default="90,80,70")
    thresholds.add_argument("-c", "--crit", required=False,
                            help="warning thresholds (5sec,1min,5min)",
                            type=str, dest='crit', default="95,90,80")

    connopts = parser.add_argument_group('Connection parameters')
    connopts.add_argument("-H", "--host", required=True,
                          help="hostname or IP address", type=str, dest='host')
    connopts.add_argument("-p", "--port", required=False,
                          help="SNMP port", type=int, dest='port', default=161)
    connopts.add_argument("-6", "--ipv6", required=False, help='Use IPv6',
                          dest='ipv6', action='store_true', default=False)
    connopts.add_argument("-t", "--timeout", required=False,
                          help="SNMP timeout", type=int, dest='timeout',
                          default=10)

    snmpopts = parser.add_argument_group('SNMPv3 parameters')
    snmpopts.add_argument("-u", "--user", required=True,
                          help="SNMPv3 user name", type=str, dest='user')
    snmpopts.add_argument("-l", "--seclevel", required=False,
                          help="SNMPv3 security level", type=str,
                          dest="v3mode",
                          choices=["authPriv", "authNoPriv"], default="authPriv")
    snmpopts.add_argument("-A", "--authkey", required=True,
                          help="SNMPv3 auth key", type=str, dest='authkey')
    snmpopts.add_argument("-X", "--privkey", required=True,
                          help="SNMPv3 priv key", type=str, dest='privkey')
    snmpopts.add_argument("-a", "--authmode", required=False,
                          help="SNMPv3 auth mode", type=str, dest='authmode',
                          default='SHA',
                          choices=['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384',
                                   'SHA512'])
    snmpopts.add_argument("-x", "--privmode", required=False,
                          help="SNMPv3 privacy mode", type=str, dest='privmode',
                          default='AES',
                          choices=['DES', '3DES', 'AES', 'AES192', 'AES256'])

    args = parser.parse_args()
    return args


async def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    # Set up TransportTarget object
    if args.ipv6:
        transport_target = await Udp6TransportTarget.create((args.host, args.port), args.timeout)
    else:
        transport_target = await UdpTransportTarget.create((args.host, args.port), args.timeout)

    # Set up UsmUserData object
    if args.v3mode == "authPriv":
        usm_user_data = UsmUserData(
            args.user, args.authkey, args.privkey,
            authProtocol=authprot[args.authmode],
            privProtocol=privprot[args.privmode]
        )
    elif args.v3mode == "authNoPriv":
        usm_user_data = UsmUserData(
            args.user, args.authkey,
            authProtocol=authprot[args.authmode]
        )
    else:
        # Should never occur - prevent pylint "possibly-used-before-assignment"
        usm_user_data = None

    snmp_engine = SnmpEngine()

    objects = bulk_walk_cmd(
        snmp_engine,
        usm_user_data,
        transport_target,
        ContextData(),
        0, 50,
        ObjectType(ObjectIdentity(table_oid)),
        lexicographicMode=False,
        lookupMib=False
    )

    iterator = [item async for item in objects]
    for error_indication, error_status, error_index, var_binds in iterator:

        if error_indication:
            # Exit if error occured during SNMP query
            exit_plugin(3, ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print(f"{error_status.prettyPrint()} at "
                  f"{error_index and var_binds[int(error_index) - 1][0] or '?'}")
        else:
            # loop over returned OIDs and append to table
            for oid_element in var_binds:
                table.append([str(oid_element[0]), str(oid_element[1])])

    snmp_engine.close_dispatcher()

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


async def main():
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
        try:
            l5sec, l1min, l5min = await asyncio.gather(
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.6', args),
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.7', args),
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.8', args),
            )
        except Exception as err:  # pylint: disable=broad-exception-caught
            exit_plugin("3", f'Exception during SNMP query: {type(err)} {err}', "NULL")

    elif args.mode == "CISCO-PROCESS-MIB_OLD":
        # Use deprecated OIDs in CISCO-PROCESS-MIB
        #     CISCO-PROCESS-MIB::cpmCPUTotal5sec
        #     CISCO-PROCESS-MIB::cpmCPUTotal1min
        #     CISCO-PROCESS-MIB::cpmCPUTotal5min
        try:
            l5sec, l1min, l5min = await asyncio.gather(
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.3', args),
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.4', args),
                get_snmp_table('1.3.6.1.4.1.9.9.109.1.1.1.1.5', args),
            )
        except Exception as err:  # pylint: disable=broad-exception-caught
            exit_plugin("3", f'Exception during SNMP query: {type(err)} {err}', "NULL")
    else:
        # Should never occur - prevent pylint E0606 "possibly-used-before-assignment"
        l5sec, l1min, l5min = None, None, None

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

        # Prevent pylint E0606 "possibly-used-before-assignment"
        val5sec, val1min, val5min = 0.0, 0.0, 0.0

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
        perfdata += (
            f'\'cpuload_5sec_{cpuid}\'={val5sec}%;{w5sec};{c5sec};0;100 '
            f'\'cpuload_1min_{cpuid}\'={val1min}%;{w1min};{c1min};0;100 '
            f'\'cpuload_5min_{cpuid}\'={val5min}%;{w5min};{c5min};0;100 '
        )

        output += f'CPU {cpuid}: (5s: {val5sec}%, 1m: {val1min}%, 5m: {val5min}%), '

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
    asyncio.run(main())
