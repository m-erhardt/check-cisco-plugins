# check_cisco_stackmodules.py

![Output of check_cisco_stackmodules.py](img/check_cisco_stackmodules-small.png?raw=true "Output of check_cisco_stackmodules.py")

## Usage

```
usage: check_cisco_stackmodules.py [-h] --host HOST [--port PORT]
                                   [--timeout TIMEOUT] --user USER
                                   [-l {authPriv,authNoPriv}] --authkey
                                   AUTHKEY --privkey PRIVKEY
                                   [--authmode {MD5,SHA,SHA224,SHA256,SHA384,SHA512}]
                                   [--privmode {DES,3DES,AES,AES192,AES256}]

Cisco stack module check plugin

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           hostname or IP address
  --port PORT           SNMP port
  --timeout TIMEOUT     SNMP timeout
  --user USER           SNMPv3 user name
  -l {authPriv,authNoPriv}, --seclevel {authPriv,authNoPriv}
                        SNMPv3 security level
  --authkey AUTHKEY     SNMPv3 auth key
  --privkey PRIVKEY     SNMPv3 priv key
  --authmode {MD5,SHA,SHA224,SHA256,SHA384,SHA512}
                        SNMPv3 auth mode
  --privmode {DES,3DES,AES,AES192,AES256}
                        SNMPv3 privacy mode
```

### Usage example
```
./check_cisco_stackmodules.py --host 1.2.3.4 \
                              --user monitoring \
                              --authmode SHA \
                              --authkey 'ABCDEF' \
                              --privmode AES \
                              --privkey '123456'
```