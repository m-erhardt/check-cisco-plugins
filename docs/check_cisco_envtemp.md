# check_cisco_envtemp.py

![Output of check_cisco_envtemp.py](img/check_cisco_envtemp-small.png?raw=true "Output of check_cisco_envtemp.py")

## Usage

```
usage: check_cisco_envtemp.py [-h] [--os {ios,nxos}] [--scale SCALE] -H HOST
                              [-p PORT] [-t TIMEOUT] -u USER
                              [-l {authPriv,authNoPriv}] -A AUTHKEY -X PRIVKEY
                              [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                              [-x {DES,3DES,AES,AES192,AES256}]

Icinga/Nagios plugin which checks temperature sensors on Cisco
switches/routers

optional arguments:
  -h, --help            show this help message and exit

Check parameters:
  --os {ios,nxos}       Switch operating system
  --scale SCALE         Scaling factor for thresholds (in percent), currently
                        only works wiht --os nxos

Connection parameters:
  -H HOST, --host HOST  hostname or IP address
  -p PORT, --port PORT  SNMP port
  -t TIMEOUT, --timeout TIMEOUT
                        SNMP timeout

SNMPv3 parameters:
  -u USER, --user USER  SNMPv3 user name
  -l {authPriv,authNoPriv}, --seclevel {authPriv,authNoPriv}
                        SNMPv3 security level
  -A AUTHKEY, --authkey AUTHKEY
                        SNMPv3 auth key
  -X PRIVKEY, --privkey PRIVKEY
                        SNMPv3 priv key
  -a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}, --authmode {MD5,SHA,SHA224,SHA256,SHA384,SHA512}
                        SNMPv3 auth mode
  -x {DES,3DES,AES,AES192,AES256}, --privmode {DES,3DES,AES,AES192,AES256}
                        SNMPv3 privacy mode
```

### Usage example
```
./check_cisco_envtemp.py --host 1.2.3.4 \
                         --user monitoring \
                         --authmode SHA \
                         --authkey 'ABCDEF' \
                         --privmode AES \
                         --privkey '123456' \
                        --os ios
```
### Parameters
* `--os`
  * You'll need to set this parameter according to the operating system of the switch / router\
  use `ios` for Cisco IOS devices, `nxos` for Cisco NX-OS devices
* `--scale`
    * This plugin uses the thresholds provided by Cisco via SNMP.\
    Having overall `--warn`/`--crit` thresholds does not make sense as a temperature sensor which is located directly on the backplane naturally gives higher readings than a temperature sensor which is located at the air intake.\
    If you would like to generate alarms before reaching the thresholds defined by Cisco you can set `--scale 80` to set your thresholds at 80% of the original thresholds
