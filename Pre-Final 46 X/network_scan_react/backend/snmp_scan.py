from pysnmp.hlapi import *

def snmp_get(ip, oid):

    iterator = getCmd(
        SnmpEngine(),
        CommunityData("public"),
        UdpTransportTarget((ip,161), timeout=1, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication,errorStatus,errorIndex,varBinds = next(iterator)

    if errorIndication or errorStatus:
        return ""

    for varBind in varBinds:
        return str(varBind[1])

    return ""

def scan_snmp(ip):

    try:

        description = snmp_get(ip, "1.3.6.1.2.1.1.1.0")
        name = snmp_get(ip, "1.3.6.1.2.1.1.5.0")
        contact = snmp_get(ip, "1.3.6.1.2.1.1.4.0")
        location = snmp_get(ip, "1.3.6.1.2.1.1.6.0")
        uptime = snmp_get(ip, "1.3.6.1.2.1.1.3.0")
        objectid = snmp_get(ip, "1.3.6.1.2.1.1.2.0")

    except Exception:

        return {
            "snmpEnabled": False
        }

    enabled = any([
        description,
        name,
        contact,
        location,
        uptime,
        objectid
    ])

    return {
        "snmpEnabled": enabled,
        "snmpVersion": "v2c",
        "systemDescription": description,
        "systemName": name,
        "contact": contact,
        "location": location,
        "uptime": uptime,
        "objectId": objectid
    }