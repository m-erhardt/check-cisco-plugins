#!/usr/bin/env python3
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


class TempSensor:
    """ Class for temperature sensor """

    def __init__(self, identifier: int):
        self.identifier: int = identifier
        self.value: float = None
        self.scale: int = None
        self.w_thres: float = None
        self.c_thres: float = None

    def get_value(self):
        """ Return sensor value (adjusted for scaling) """
        if self.scale == 9:
            return self.value
        if self.scale == 8:
            return self.value / 1000
        return self.value

    def get_threshold(self, severity: str):
        """ return thresholds for sensor (adjusted for scaling) """
        if severity == "warning":
            if self.w_thres is None:
                ret = None
            else:
                if self.scale == 9:
                    ret = self.w_thres
                elif self.scale == 8:
                    ret = self.w_thres / 1000
        elif severity == "critical":
            if self.c_thres is None:
                ret = None
            else:
                if self.scale == 9:
                    ret = self.c_thres
                elif self.scale == 8:
                    ret = self.c_thres / 1000
        return ret


class SensorThreshold:
    """ Class for temperature sensor """

    def __init__(self, identifier: int, belongs_to: int):
        self.identifier: int = identifier
        self.belongs_to: int = belongs_to
        self.severity: float = None
        self.value: float = None
        self.scale: float = None


def get_args():
    """ Parse Arguments """
    parser = ArgumentParser(
                 description="Icinga/Nagios plugin which checks temperature \
                             sensors on Cisco switches/routers")

    checkopts = parser.add_argument_group('Check parameters')
    checkopts.add_argument("--os", required=False, help="Switch operating system",
                           type=str, dest='os',
                           default='ios', choices=['ios', 'nxos'])
    checkopts.add_argument("--scale", required=False,
                           help="Scaling factor for thresholds (in percent), \
                           currently only works wiht --os nxos",
                           type=float, dest='scale')

    connopts = parser.add_argument_group('Connection parameters')
    connopts.add_argument("-H", "--host", required=True,
                          help="hostname or IP address", type=str, dest='host')
    connopts.add_argument("-p", "--port", required=False, help="SNMP port",
                          type=int, dest='port', default=161)
    connopts.add_argument("-t", "--timeout", required=False, help="SNMP timeout",
                          type=int, dest='timeout', default=10)

    snmpopts = parser.add_argument_group('SNMPv3 parameters')
    snmpopts.add_argument("-u", "--user", required=True, help="SNMPv3 user name",
                          type=str, dest='user')
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


def check_ios_device(args):
    """ check Cisco IOS device """
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
        # Check if we received data via SNMP, otherwise exit with state
        # Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    # Create perfdata and output strings
    perfdata = ""
    output = "Sensor readings are: "
    for i, _ in enumerate(temp_values):
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
    for i, _ in enumerate(temp_values):
        if float(temp_values[i][1]) >= float(temp_thresholds[i][1]) and \
           float(temp_thresholds[i][1]) != 0:
            returncode = "2"

    exit_plugin(returncode, output, perfdata)


def check_nxos_device(args):
    """ check Cisco IOS device """
    # Cisco NX-OS switch, using CISCO-ENTITY-SENSOR-MIB

    # Get sensor type (CISCO-ENTITY-SENSOR-MIB::entSensorType)
    sensor_type = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.1', args)

    # Get sensor type (CISCO-ENTITY-SENSOR-MIB::entSensorValue)
    sensor_values = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.4', args)

    # Get sensor threshold table (CISCO-ENTITY-SENSOR-MIB::entSensorThresholdTable)
    sensor_thresholds = get_snmp_table('1.3.6.1.4.1.9.9.91.1.2.1', args)

    # Get sensor scale (CISCO-ENTITY-SENSOR-MIB::entSensorScale)
    sensor_scale = get_snmp_table('1.3.6.1.4.1.9.9.91.1.1.1.1.2', args)

    if len(sensor_type) == 0 or len(sensor_values) == 0 or \
       len(sensor_thresholds) == 0 or len(sensor_scale) == 0:
        # Check if we received data via SNMP, otherwise exit with state
        # Unknown
        exit_plugin("3", "No data returned via SNMP", "NULL")

    # Extract temperature sensors and create list of TempSensor Objects
    tempsensors = []
    for entry in sensor_type:
        if entry[1] == "8":
            tempsensors.append(TempSensor(int(entry[0].split(".")[-1:][0])))

    # Append value and scale to TempSensor Objects in tempsensors
    for entry in tempsensors:

        for value in sensor_values:
            if int(value[0].split(".")[-1:][0]) == entry.identifier:
                entry.value = float(value[1])
                break

        for scale in sensor_scale:
            if int(scale[0].split(".")[-1:][0]) == entry.identifier:
                entry.scale = int(scale[1])
                break

    thresholds = []
    for entry in sensor_thresholds:
        # Extract thresholds which have comparision operator greaterOrEqual(4)

        if entry[0].split(".")[13] == "3" and entry[1] == "4":
            s_id = int(entry[0].split(".")[15])
            belongs_to = int(entry[0].split(".")[14])

            thresholds.append(SensorThreshold(s_id, belongs_to))

    for entry in thresholds:
        # Add severety and value to SensorThreshold-Objects in thresholds
        for threshold in sensor_thresholds:
            if entry.belongs_to == int(threshold[0].split(".")[14]) and \
               entry.identifier == int(threshold[0].split(".")[15]) and \
               threshold[0].split(".")[13] == "2":
                entry.severity = threshold[1]

            if entry.belongs_to == int(threshold[0].split(".")[14]) and \
               entry.identifier == int(threshold[0].split(".")[15]) and \
               threshold[0].split(".")[13] == "4":
                entry.value = threshold[1]

    for sensor in tempsensors:
        # Add thresholds from SensorThreshold-Objects in thresholds to
        # TempSensor-Objects in tempsensors

        for threshold in thresholds:
            if sensor.identifier == threshold.belongs_to:

                if threshold.severity == "30":
                    sensor.c_thres = float(threshold.value)

                elif threshold.severity == "20":
                    sensor.w_thres = float(threshold.value)

                elif threshold.severity == "10" and sensor.w_thres is None:
                    sensor.w_thres = float(threshold.value)

    # Set return code and generate output and perfdata strings
    returncode = "0"
    perfdata = ""
    output = "Sensor readings are: "

    for sensor in tempsensors:
        # loop through temperature sensors

        # Append to perfdata and output string
        perfdata += (f'\'temp_{ sensor.identifier }\'={ sensor.get_value() }'
                     f';{ sensor.get_threshold("warning") or "" };'
                     f'{ sensor.get_threshold("critical") or "" };; ')
        output += f'{ sensor.get_value() }°C, '

        # Calculate return code
        if sensor.get_threshold("critical") is not None:
            if sensor.get_value() >= sensor.get_threshold("critical"):
                returncode = "2"
        if sensor.get_threshold("warning") is not None:
            if sensor.get_value() >= sensor.get_threshold("warning") and \
               returncode != "2":
                returncode = "1"

    # Remove last comma from output string
    output = output.rstrip(', ')

    exit_plugin(returncode, output, perfdata)


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
        check_ios_device(args)

    if args.os == "nxos":
        check_nxos_device(args)


if __name__ == "__main__":
    main()
