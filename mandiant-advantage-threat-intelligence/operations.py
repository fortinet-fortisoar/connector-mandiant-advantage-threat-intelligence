""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .mandiant_api_auth import *
from .constants import *
from connectors.core.connector import get_logger, ConnectorError
import requests, json, datetime, time

logger = get_logger('mandiant-advantage-threat-intelligence')


def make_rest_call(endpoint, method, connector_info, config, data=None, params=None):
    try:
        co = MandiantAuth(config)
        url = co.host + endpoint
        token = co.validate_token(config, connector_info)
        logger.debug("Token: {0}".format(token))
        logger.debug("Endpoint URL: {0}".format(url))
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/vnd.oasis.stix+json; version=2.1',
                   'X-App-Name': 'fortisoar.fortinet.v1.0',
                   'Authorization': token}
        response = requests.request(method, url, headers=headers, verify=co.verify_ssl, data=data, params=params)
        logger.debug("Response: {0}".format(response))
        if response.status_code == 200:
            logger.info('Successfully got response for url {0}'.format(url))
            return response.json()
        elif response.status_code == 204:
            return dict()
        else:
            raise ConnectorError("{0}: {1}".format(response.status_code, response.content))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid endpoint or credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def build_payload(params):
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    logger.debug("Query Parameters: {0}".format(payload))
    return payload


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return int(epoch)


def get_indicators(config, params, connector_info):
    try:
        endpoint = "/v4/indicator"
        start_epoch = params.get('start_epoch')
        if 'T' in start_epoch:
            start_epoch = convert_datetime_to_epoch(start_epoch)
        end_epoch = params.get('end_epoch')
        if 'T' in end_epoch:
            end_epoch = convert_datetime_to_epoch(end_epoch)
        payload = {
            'limit': params.get('limit'),
            'gte_mscore': params.get('gte_mscore'),
            'exclude_osint': params.get('exclude_osint'),
            'include_reports': params.get('include_reports'),
            'report_limit': params.get('report_limit'),
            'include_campaigns': params.get('include_campaigns'),
            'start_epoch': start_epoch,
            'end_epoch': end_epoch,
            'next': params.get('next'),
            'sort_by': params.get('sort_by'),
            'sort_order': SORT_ORDER.get(params.get('sort_order'))
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_actors(config, params, connector_info):
    try:
        endpoint = "/v4/actor"
        payload = build_payload(params)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_actor_details(config, params, connector_info):
    try:
        endpoint = "/v4/actor/{0}".format(params.get('id'))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_malware(config, params, connector_info):
    try:
        endpoint = "/v4/malware"
        payload = build_payload(params)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_malware_details(config, params, connector_info):
    try:
        endpoint = "/v4/malware/{0}".format(params.get('id'))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaign(config, params, connector_info):
    try:
        endpoint = "/v4/campaign"
        payload = check_payload(params)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaign_details(config, params, connector_info):
    try:
        endpoint = "/v4/campaign/{0}".format(params.get('id'))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_vulnerability(config, params, connector_info):
    try:
        endpoint = "/v4/vulnerability"
        start_epoch = params.get('start_epoch')
        if 'T' in start_epoch:
            start_epoch = convert_datetime_to_epoch(start_epoch)
        end_epoch = params.get('end_epoch')
        if 'T' in end_epoch:
            end_epoch = convert_datetime_to_epoch(end_epoch)
        payload = {
            'limit': params.get('limit'),
            'start_epoch': start_epoch,
            'end_epoch': end_epoch,
            'next': params.get('next'),
            'sort_by': params.get('sort_by'),
            'sort_order': SORT_ORDER.get(params.get('sort_order')),
            'rating_types': ','.join(params.get('rating_types').lower()) if params.get('rating_types') else '',
            'risk_ratings': ','.join(params.get('risk_ratings').upper()) if params.get('risk_ratings') else ''
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_reports(config, params, connector_info):
    try:
        endpoint = "/v4/reports"
        start_epoch = params.get('start_epoch')
        if 'T' in start_epoch:
            start_epoch = convert_datetime_to_epoch(start_epoch)
        end_epoch = params.get('end_epoch')
        if 'T' in end_epoch:
            end_epoch = convert_datetime_to_epoch(end_epoch)
        payload = {
            'limit': params.get('limit'),
            'offset': params.get('offset'),
            'start_epoch': start_epoch,
            'end_epoch': end_epoch,
            'next': params.get('next')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_report_details(config, params, connector_info):
    try:
        endpoint = "/v4/report/{0}".format(params.get('id'))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_indicator_details(config, params, connector_info):
    try:
        endpoint = "/v4/indicator"
        payload = {
            "requests": [
                {
                    "values": [params.get('value')]
                }
            ],
            "include_campaigns": True
        }
        response = make_rest_call(endpoint, 'POST', connector_info, config, data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_indicators': get_indicators,
    'get_actors': get_actors,
    'get_actor_details': get_actor_details,
    'get_malware': get_malware,
    'get_malware_details': get_malware_details,
    'get_campaign': get_campaign,
    'get_campaign_details': get_campaign_details,
    'get_vulnerability': get_vulnerability,
    'get_reports': get_reports,
    'get_report_details': get_report_details,
    'get_indicator_details': get_indicator_details
}
