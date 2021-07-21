#!/bin/env python3.6
"""
###############################################################################
# check_cisco_envtemp.py
# Icinga/Nagios plugin that checks the status of all temperature sensors on a
# Cisco Switch/Router via SNMPv3 using the CISCO-ENVMON-MIB
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
                 description="Icinga/Nagios plugin which checks temperature \
                             sensors on Cisco switches/routers",
                 epilog=""
             )
    parser.add_argument("-H", "--host", required=True,
                        help="hostname or IP address", type=str, dest='host')
    parser.add_argument("-p", "--port", required=False, help="SNMP port",
                        type=int, dest='port', default=161)
    parser.add_argument("-t", "--timeout", required=False, help="SNMP timeout",
                        type=int, dest='timeout', default=10)
    parser.add_argument("-u", "--user", required=True, help="SNMPv3 user name",
                        type=str, dest='user')
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
    parser.add_argument("--os", required=False, help="Switch operating system",
                        type=str, dest='os',
                        default='ios', choices=['ios', 'nxos'])
    parser.add_argument("--scale", required=False,
                        help="Scaling factor for thresholds (in percent), \
                        currently only works wiht --os nxos",
                        type=float, dest='scale')
    args = parser.parse_args()
    return args


def get_snmp_table(table_oid, args):
    """ get SNMP table """

    # initialize empty list for return object
    table = []

    iterator = bulkCmd(
            SnmpEngine(),
            UsmUserData(args.user, args.authkey, args.privkey,
                        authProtocol=authprot[args.authmode],
                        privProtocol=privprot[args.privmode]),
            UdpTransportTarget((args.host, args.port), timeout=args.timeout),
            ContextData(),
            0, 50,
            ObjectType(ObjectIdentity(table_oid)),
            lexicographicMode=False
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
            table.append(str(var_binds[0]).split("="))
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

    if args.os == "ios":
        # Cisco IOS switch, using CISCO-ENVMON-MIB

        # Get temperature values
        # (CISCO-ENVMON-MIB::ciscoEnvMonTemperatureStatusValue)
        temp_values = get_snmp_table('1.3.6.1.4.1.9.9.13.1.3.1.3', args)

        # Get vendor defined thresholds
        # (CISCO-ENVMON-MIB::ciscoEnvMonTemperatureThreshold)
        temp_thresholds = get_snmp_table('1.3.6.1.4.1.9.9.13.1.3.1.4', args)

        # Get temperature state (CISCO-ENVMON-MIB::ciscoEnvMonTemperatureState)
        temp_state = get_snmp_table('1.3.6.1.4.1.9.9.13.1.3.1.6', args)

        # Remove everything except identifier from SNMP OID
        # ('SNMPv2-SMI::enterprises.9.9.13.1.3.1.3.1008 ' -> '1008')
        # And strip blanks from OID values (' 42' -> '42')
        for entry in chain(temp_values, temp_thresholds, temp_state):
            entry[0] = entry[0].strip().split(".")[-1:]
            entry[0] = "".join(map(str, entry[0]))
            entry[1] = entry[1].strip()

        if len(temp_values) == 0 or len(temp_thresholds) == 0 or \
            len(temp_state) == 0:
            # Check if we received data via SNMP, otherwise exit with state Unknown
            exit_plugin("3", "No data returned via SNMP", "NULL")

        # Create perfdata and output strings
        perfdata = ""
        output = "Sensor readings are: "
        for i, val  in enumerate(temp_values):
            # loop through sensors and construct return and perfdata string

            if args.scale is not None:
                # Do not apply MIB-definded thresholds,
                # instead scale them by <threshold_scale>%
                temp_thresholds[i][1] = round(float(temp_thresholds[i][1]) *
                                              (args.scale / 100), 1)

            perfdata += "\'temp_" + str(temp_values[i][0]) + "\'=" + \
                        str(temp_values[i][1]) + ";;" + \
                        str(temp_thresholds[i][1]) + ";; "
            output += str(temp_values[i][1]) + "°C, "

        # Remove last comma from output string
        output = output.rstrip(', ')

        # Calculate return code
        returncode = "0"
        for i, val in enumerate(temp_values):
            if float(temp_values[i][1]) >= float(temp_thresholds[i][1]) and \
               float(temp_thresholds[i][1]) != 0:
                returncode = "2"

        exit_plugin(returncode, output, perfdata)

    if args.os == "nxos":
        # Cisco NX-OS switch, using CISCO-ENTITY-SENSOR-MIB

        # Get sensor type (CISCO-ENTITY-SENSOR-MIB::entSensorType)
        sensor_type = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.1', args)

        # Get sensor type (CISCO-ENTITY-SENSOR-MIB::entSensorValue)
        sensor_values = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.4', args)

        # Get sensor thresholds (CISCO-ENTITY-SENSOR-MIB::entSensorThresholdValue)
        sensor_thresholds = get_snmp_table('1.3.6.1.4.1.9.9.91.1.2.1.1.4', args)

        # Get sensor scale (CISCO-ENTITY-SENSOR-MIB::entSensorScale)
        sensor_scale = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.2', args)

        # Format returned SNMP data to lists
        for entry in chain(sensor_type, sensor_values, sensor_scale):
            entry[0] = entry[0].strip().split(".")[-1:]
            entry[0] = "".join(map(str, entry[0]))
            entry[1] = entry[1].strip()

        for entry in sensor_thresholds:
            entry[0] = entry[0].strip().split(".")[-2:]
            entry[1] = entry[1].strip()

        if len(sensor_type) == 0 or len(sensor_values) == 0 or \
            len(sensor_thresholds) == 0 or len(sensor_scale) == 0:
            # Check if we received data via SNMP, otherwise exit with state Unknown
            exit_plugin("3", "No data returned via SNMP", "NULL")

        # Create list with identifiers of temperature sensors from
        # CISCO-ENTITY-SENSOR-MIB::entSensorType
        tempsensorids = []
        for i in sensor_type:
            if str(i[1]) == "8":
                tempsensorids.append(i[0])

        # Set return code and generate output and perfdata strings
        returncode = "0"
        perfdata = ""
        output = "Sensor readings are: "

        for i in tempsensorids:
            # loop through temperature sensors
            sensor = i

            for entry in sensor_values:
                # Get value for sensor ID
                if str(entry[0]) == str(sensor):
                    val = float(entry[1])

            for entry in sensor_thresholds:
                # Get warn and crit thresholds for sensor ID
                if str(entry[0][0]) == str(sensor):
                    if str(entry[0][1]) == "1":
                        warn = float(entry[1])
                    if str(entry[0][1]) == "2":
                        crit = float(entry[1])

            for entry in sensor_scale:
                # Get scaling factor for sensor value
                if str(entry[0]) == str(sensor):
                    scale = str(entry[1])

            if str(scale) == "8":
                # Scaling factor is milli(8), divide val, warn and crin /1000
                val = round(val / 1000, 2)
                warn = warn / 1000
                crit = crit / 1000

            if args.scale is not None:
                # Do not apply MIB-definded thresholds,
                # instead scale them by <threshold_scale>%
                warn = round(warn * (args.scale / 100), 1)
                crit = round(crit * (args.scale / 100), 1)

            # Append to perfdata and output string
            perfdata += ''.join(["\'temp_", str(sensor), "\'=", str(val), ";",
                                 str(warn), ";", str(crit), ";; "])
            output += ''.join([str(val), "°C, "])

            # Calculate return code
            if val >= crit > 0:
                returncode = "2"
            elif (val >= warn > 0) and (returncode != "2"):
                returncode = "1"

        # Remove last comma from output string
        output = output.rstrip(', ')

        exit_plugin(returncode, output, perfdata)

if __name__ == "__main__":
    main()
