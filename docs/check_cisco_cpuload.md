# check_cisco_cpuload.py

![Output of check_cisco_cpuload.py](img/check_cisco_cpuload-small.png?raw=true "Output of check_cisco_cpuload.py")

## Usage

```
usage: check_cisco_cpuload.py [-h]
                              [--mode {CISCO-PROCESS-MIB_NEW,CISCO-PROCESS-MIB_OLD}]
                              [-w WARN] [-c CRIT] -H HOST [-p PORT]
                              [-t TIMEOUT] -u USER [-l {authPriv,authNoPriv}]
                              -A AUTHKEY -X PRIVKEY
                              [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                              [-x {DES,3DES,AES,AES192,AES256}]

Icinga/Nagios plugin which checks cpu load on Cisco switches/routers

optional arguments:
  -h, --help            show this help message and exit

Check parameters:
  --mode {CISCO-PROCESS-MIB_NEW,CISCO-PROCESS-MIB_OLD}

Thresholds:
  -w WARN, --warn WARN  warning thresholds (5sec,1min,5min)
  -c CRIT, --crit CRIT  warning thresholds (5sec,1min,5min)

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
./check_cisco_cpuload.py --host 1.2.3.4 \
                         --user monitoring \
                         --authmode SHA \
                         --authkey 'ABCDEF' \
                         --privmode AES \
                         --privkey '123456' \
                         --warn '90,80,70'
                         --crit '95,90,80'
                         --mode CISCO-PROCESS-MIB_NEW
```
### Parameters
* `--mode`
  * You'll need to set this parameter according to your Switch model.\
  `CISCO-PROCESS-MIB_OLD` works for Cisco IOS devices, `CISCO-PROCESS-MIB_NEW` for Cisco NX-OS devices
