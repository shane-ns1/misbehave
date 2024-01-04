import logging
import os
#import requests
import urllib3

import ns1
import ns1.rest.errors
import ns1.rest.zones

class MissingAPIKEY(Exception):
    pass


def get_localdev_config(service: str) -> str:
    # Missing API key is a problem.
    if 'LOCALDEV_APIKEY' not in os.environ:
        raise MissingAPIKEY
    api_key = os.environ['LOCALDEV_APIKEY']

    # Missing operator key is not (necessarily) a problem.
    operator_key = os.getenv('LOCALDEV_OPERATOR_KEY')

    # The port depends on which daemon we are talking to.
    if service == "apid":
        port = 18080
    elif service == "nexusd":
        port = 18000
    else:
        raise ValueError(f"unknown service {service!r}")

    config_file_contents = {
        "default_key": "misbehave",
        "endpoint": "127.0.0.1",
        "port": str(port),
        "ignore-ssl-errors": True,
        "keys": {
            "misbehave": {
                "key": api_key,
                "desc": "user key",
            },
        },
    }
    if operator_key:
        config_file_contents["keys"]["misbehave_operator"] = {
            "key": operator_key,
            "desc": "operator key",
        }

    return config_file_contents


def test_self_referential_alias(apid_api: ns1.NS1, nexusd_api: ns1.NS1) -> None:
    logging.info("test self-referrential ALIAS (should not be allowed)")
    zone_name = "alias-loop.test"
    record_name = "self.alias-loop.test"

    # Clean up any previous versions of the zone.
    try:
        old_zone = nexusd_api.loadZone(zone_name)
    except ns1.rest.errors.ResourceException:
        old_zone = None
    if old_zone:
        old_zone.delete()

    # Create a zone to put our ALIAS loop in.
    zone = apid_api.createZone(zone_name)

    # Try to create a self-referential ALIAS record.
    alias_ex = None
    try:
        fields = [record_name,]
        record = zone.add_ALIAS(record_name, [{'answer': fields}])
    except ns1.rest.errors.ResourceException as ex:
        alias_ex = ex

    assert alias_ex is not None, "ALIAS record to itself should not work"
    expected = "server error: ALIAS records must not reference themselves"
    test_alert = f"Unexpected exception adding ALIAS record: {alias_ex}"
    assert alias_ex.message == expected, test_alert

    # Clean up our zone.
    cleanup_zone = nexusd_api.loadZone(zone_name)
    cleanup_zone.delete()


def test_record_urlfwd(apid_api: ns1.NS1, nexusd_api: ns1.NS1) -> None:
    logging.info("test URLFWD record")
    zone_name = "urlfwd-record.test"
    record_name = "urlfwd.urlfwd-record.test"

    # Clean up any previous versions of the zone.
    try:
        old_zone = nexusd_api.loadZone(zone_name)
    except ns1.rest.errors.ResourceException:
        old_zone = None
    if old_zone:
        old_zone.delete()

    # Create a zone.
    zone = apid_api.createZone(zone_name)

    # Try to create a URLFWD record.
    fields = ["/*", "http://backend.com", 0, 0, 0,]
    record = zone.add_URLFWD(record_name, [{'answer': fields}])

    # Clean up our zone.
    cleanup_zone = nexusd_api.loadZone(zone_name)
    cleanup_zone.delete()


def test_dnssec_record_block(apid_api: ns1.NS1, nexusd_api: ns1.NS1) -> None:
    logging.info("test DNSSEC records block")
    zone_name = "dnssec-rec.test"
    record_info = [
        {
            "name": "nsec.dnssec-rec.test",
            "type": "NSEC",
            "fields": ["nsec-next.dnssec-rec.test", "AAAA", "NSEC"],
        },
        {
            "name": "31q6habspul9notdp67v0t80ibdc56q4.dnssec-rec.test",
            "type": "NSEC3",
            "fields": [1, 0, 0, "-", "31Q6TSHND09LH0JA6R5I03DH6ATRI145", "A"],
        },
        {
            "name": "dnssec-rec.test",
            "type": "NSEC3PARAM",
            "fields": [1, 0, 0, "-"],
        },
        {
            "name": "dnskey.dnssec-rec.test",
            "type": "DNSKEY",
            "fields": [257, 3, 13,
                       "aeDdFmc/JLPyva7Y4bS2SFbfWmxaiSrnqwgs+D1PKSPS",
                       "ruxIRH+6gHLhJ4XYIzrSaT3uk6rsx3c5jV8U4B8O+g==",],
        },
        {
            "name": "rrsig.dnssec-rec.test",
            "type": "RRSIG",
            "fields": [257, 3, 13,
                       "aeDdFmc/JLPyva7Y4bS2SFbfWmxaiSrnqwgs+D1PKSPS",
                       "ruxIRH+6gHLhJ4XYIzrSaT3uk6rsx3c5jV8U4B8O+g==",],
        },
    ]

    # Clean up any previous versions of the zone.
    try:
        old_zone = nexusd_api.loadZone(zone_name)
    except ns1.rest.errors.ResourceException:
        old_zone = None
    if old_zone:
        old_zone.delete()

    # Create a zone.
    zone = apid_api.createZone(zone_name)

    # Try to create each DNSSEC record.
    for info in record_info:
        create_type = info['type']
        create_method = getattr(zone, f'add_{create_type}')

        dnssec_ex = None
        try:
            record = create_method(info['name'], [{'answer': info['fields']}])
        except ns1.rest.errors.ResourceException as ex:
            dnssec_ex = ex

        errmsg = f"DNSSEC record type {create_type} should be blocked"
        assert dnssec_ex is not None, errmsg
        expected= "server error: Operation on DNSSEC record is not allowed"
        test_alert = f"Unexpected exception adding DNSSEC record: {dnssec_ex}"
        assert dnssec_ex.message == expected, test_alert

    # Clean up our zone.
    cleanup_zone = nexusd_api.loadZone(zone_name)
    cleanup_zone.delete()


def main():
    logging.debug('starting')
    apid_config = ns1.config.Config()
    apid_config.loadFromDict(get_localdev_config('apid'))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    apid_api = ns1.NS1(config=apid_config)
    nexusd_config = ns1.config.Config()
    nexusd_config.loadFromDict(get_localdev_config('nexusd'))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    nexusd_api = ns1.NS1(config=nexusd_config)
    logging.debug('configuration & setup complete')
   
    logging.debug('running tests')
    test_self_referential_alias(apid_api, nexusd_api)
    test_record_urlfwd(apid_api, nexusd_api)
    test_dnssec_record_block(apid_api, nexusd_api)


if __name__ == '__main__':
    main()
