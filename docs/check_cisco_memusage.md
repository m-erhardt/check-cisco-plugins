# check_cisco_memusage.py

![Output of check_cisco_memusage.py](img/check_cisco_memusage-small.png?raw=true "Output of check_cisco_memusage.py")

## Usage

```
usage: check_cisco_memusage.py [-h] -H HOST [-p PORT] [-t TIMEOUT] -u USER
                               [-l {authPriv,authNoPriv}] -A AUTHKEY -X
                               PRIVKEY
                               [-a {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                               [-x {DES,3DES,AES,AES192,AES256}] [-w WARN]
                               [-c CRIT]
                               [--mib {CISCO-PROCESS-MIB,CISCO-MEMORY-POOL-MIB}]

Icinga/Nagios plugin which checks system memory usage on Cisco
switches/routers

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  hostname or IP address
  -p PORT, --port PORT  SNMP port
  -t TIMEOUT, --timeout TIMEOUT
                        SNMP timeout
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
  -w WARN, --warn WARN  warning threshold (in percent)
  -c CRIT, --crit CRIT  warning thresholds (in percent)
  --mib {CISCO-PROCESS-MIB,CISCO-MEMORY-POOL-MIB}
                        use OIDs from this MIB
```

### Usage example
```
.check_cisco_memusage.py --host 1.2.3.4 \
                         --user monitoring \
                         --authmode SHA \
                         --authkey 'ABCDEF' \
                         --privmode AES \
                         --privkey '123456' \
                         --warn 85 \
                         --crit 90 \
                         --mib CISCO-MEMORY-POOL-MIB
```
### Parameters
* `--mib`
  * use `CISCO-MEMORY-POOL-MIB` for Cisco Catalyst 2960-S and 2960-X, `CISCO-PROCESS-MIB` for all other models
