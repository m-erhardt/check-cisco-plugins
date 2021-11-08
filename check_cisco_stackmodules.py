#!/usr/bin/env python3
"""
###############################################################################
# check_cisco_stackmodules.py
# Nagios plugin/script that checks the status of all stack modules of a Cisco
# Switch/Router via SNMPv3 using the CISCO-STACKWISE-MIB
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

cswSwitchState = {
    "1": "waiting",
    "2": "progressing",
    "3": "added",
    "4": "ready",
    "5": "sdmMismatch",
    "6": "verMismatch",
    "7": "featureMismatch",
    "8": "newMasterInit",
    "9": "provisioned",
    "10": "invalid",
    "11": "removed"
}

cswStackPortOperStatus = {
    "1": "up",
    "2": "down",
    "3": "forcedDown"
}


def get_args():
    """ Parse Arguments """
    parser = ArgumentParser(
                 description="Cisco stack module check plugin",
                 epilog=""
             )
    parser.add_argument("--host", required=True, help="hostname or IP address",
                        type=str, dest='host')
    parser.add_argument("--port", required=False, help="SNMP port", type=int,
                        dest='port', default=161)
    parser.add_argument("--timeout", required=False, help="SNMP timeout",
                        type=int, dest='timeout', default=10)
    parser.add_argument("--user", required=True, help="SNMPv3 user name",
                        type=str, dest='user')
    parser.add_argument("--authkey", required=True, help="SNMPv3 auth key",
                        type=str, dest='authkey')
    parser.add_argument("--privkey", required=True, help="SNMPv3 priv key",
                        type=str, dest='privkey')
    parser.add_argument("--authmode", required=False, help="SNMPv3 auth mode",
                        type=str, dest='authmode',
                        default='SHA',
                        choices=['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384',
                                 'SHA512'])
    parser.add_argument("--privmode", required=False,
                        help="SNMPv3 privacy mode", type=str, dest='privmode',
                        default='AES',
                        choices=['DES', '3DES', 'AES', 'AES192', 'AES256'])
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
            lexicographicMode=False
    )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            exit_plugin("3", ''.join(['SNMP error: ', str(error_indication)]), "")
        elif error_status:
            print('%s at %s' % (error_status.prettyPrint(),
                                error_index and
                                var_binds[int(error_index) - 1][0] or '?'))
        else:
            # split OID and value into two fields and append to return element
            table.append(str(var_binds[0]).split("="))
    # return list with all OIDs/values from snmp table
    return table


def exit_plugin(returncode, output, perfdata):
    """ Check status and exit accordingly """
    if returncode == "3":
        print("UNKNOWN - " + str(output))
        sys.exit(3)
    if returncode == "2":
        if perfdata == "":
            print(f"CRITICAL - {output}")
        else:
            print(f"CRITICAL - {output} | {perfdata}")
        sys.exit(2)
    if returncode == "1":
        if perfdata == "":
            print(f"WARNING - {output}")
        else:
            print(f"WARNING - {output} | {perfdata}")
        sys.exit(1)
    elif returncode == "0":
        if perfdata == "":
            print(f"OK - {output}")
        else:
            print(f"OK - {output} | {perfdata}")
        sys.exit(0)


def main():
    """ Main program code """

    # Get Arguments
    args = get_args()

    # Get switch module state (CISCO-STACKWISE-MIB::cswSwitchState)
    module_state_table = get_snmp_table('1.3.6.1.4.1.9.9.500.1.2.1.1.6', args)

    # Get switch stack port state (CISCO-STACKWISE-MIB::cswStackPortOperStatus)
    port_state_table = get_snmp_table('1.3.6.1.4.1.9.9.500.1.2.2.1.1', args)

    # Summarize state of all stack modules
    module_states = []
    for entry in module_state_table:
        module_states.append(entry[1].strip())

    # Summarize state of all stack ports
    port_states = []
    for entry in port_state_table:
        port_states.append(entry[1].strip())

    # Replace status code with status strings
    # for i in range(len(module_states)):
    for i, _ in enumerate(module_states):
        module_states[i] = cswSwitchState[module_states[i]]
    for i, _ in enumerate(port_states):
        port_states[i] = cswStackPortOperStatus[port_states[i]]

    # Initialize return state ("0" = "OK")
    retstate = "0"

    # check if any modules are not in state "ready"
    for i, _ in enumerate(module_states):
        if module_states[i] != "ready":
            retstate = "2"

    # check if any stack ports are not in state "up"
    for i, _ in enumerate(port_states):
        if port_states[i] != "up":
            retstate = "2"

    if retstate == "2":
        output = ''.join(['Switch states: \"',
                          str(",".join(module_states)),
                          '\", Stack port states: \"',
                          str(",".join(port_states)), '\"'])
        exit_plugin("2", output, "")
    elif retstate == "0":
        output = ''.join([str(len(module_states)),
                          " switches are \"ready\" and ", str(len(port_states)),
                          " stack ports are \"up\""])
        exit_plugin("0", output, "")


if __name__ == "__main__":
    main()
