"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from .mandiant_api_auth import *
from connectors.core.connector import get_logger, ConnectorError
import requests, json, datetime, time

logger = get_logger('mandiant-threat-intel')

errors = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    500: 'Internal Server Error',
    502: 'Gateway Error',
    504: 'Gateway Error'
}


def make_rest_call(endpoint, method, connector_info, config, data=None, params=None):
    try:
        co = MandiantAuth(config)
        url = co.host + endpoint
        token = co.validate_token(config, connector_info)
        logger.debug("Token: {0}".format(token))
        logger.debug("Endpoint URL: {0}".format(url))
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'X-App-Name': 'fortisoar.fortinet.v1.0',
                   'Authorization': token}
        logger.debug("Headers: {0}".format(headers))
        response = requests.request(method, url, headers=headers, verify=co.verify_ssl, data=data, params=params)
        logger.debug("Response: {0}".format(response))
        if response.status_code == 200:
            logger.info('Successfully got response for url {0}'.format(url))
            return response.json()
        elif response.status_code == 204:
            return dict()
        elif response.status_code == 404:
            return {"Message": "Not Found", "http_status": "404"}
        else:
            raise ConnectorError("{0}".format(errors.get(response.status_code)))
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
        endpoint = "/collections/indicators/objects"
        added_after = params.get('added_after')
        if 'T' in added_after:
            added_after = convert_datetime_to_epoch(added_after)
        status = params.get('status')
        payload = {
            'added_after': added_after,
            'length': params.get('length'),
            'match.id': params.get('id'),
            'match.status': status.lower() if status else ''
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def extract_indicators(response, indicators):
    for ind in response:
        if ind.get('type') == 'indicator':
            indicators.append(ind)
    return indicators


def fetch_indicators(config, params, connector_info):
    try:
        indicators = []
        endpoint = "/collections/indicators/objects"
        added_after = params.get('added_after')
        if 'T' in added_after:
            added_after = convert_datetime_to_epoch(added_after)
        status = params.get('status')
        payload = {
            'added_after': added_after,
            'length': params.get('length'),
            'match.id': params.get('id'),
            'match.status': status.lower() if status else ''
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        if bool(response):
            extract_indicators(response.get('objects'), indicators)
            response['objects'] = indicators
            return response
        return {"objects": []}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_reputation_of_indicators(config, params, connector_info):
    try:
        indicator_value = params.get('indicatorValue')
        tempList = []
        tempList.append(indicator_value)
        endpoint = "/v4/indicator"
        data = {'requests': [{'values': tempList}]}
        jsonData = json.dumps(data)
        logger.debug("JSONDATA: {0}".format(jsonData))
        response = make_rest_call(endpoint, 'POST', connector_info, config, data=jsonData)
        logger.debug("Response: {0}".format(response))
        if bool(response):
            return response
        return {"objects": []}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_reports(config, params, connector_info):
    try:
        endpoint = "/collections/reports/objects"
        status = params.get('status')
        subscription = params.get('subscription')
        report_type = params.get('report_type')
        added_after = params.get('added_after')
        if 'T' in added_after:
            added_after = convert_datetime_to_epoch(added_after)
        payload = {
            'added_after': added_after,
            'length': params.get('length'),
            'match.report_id': params.get('report_id'),
            'match.status': status.lower() if status else '',
            'match.document_id': params.get('document_id'),
            'match.subscription': subscription.lower() if subscription else '',
            'match.report_type': report_type if report_type else '',
            'match.actor_name': params.get('actor_name'),
            'match.malware_name': params.get('malware_name')
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_alerts(config, params, connector_info):
    try:
        endpoint = "/collections/alerts/objects"
        alert_type = params.get('alert_type')
        alert_categories = params.get('alert_categories')
        alert_status = params.get('alert_status')
        alert_severity = params.get('alert_severity')
        added_after = params.get('added_after')
        if 'T' in added_after:
            added_after = convert_datetime_to_epoch(added_after)
        payload = {
            'added_after': added_after,
            'length': params.get('length'),
            'match.alert_type': alert_type.lower() if alert_type else '',
            'match.alert_categories': alert_categories.lower() if alert_categories else '',
            'match.alert_status': alert_status.lower() if alert_status else '',
            'match.id': params.get('id'),
            'match.alert_severity': alert_severity.lower() if alert_severity else ''
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_collections(config, params, connector_info):
    try:
        endpoint = "/collections/search"
        payload = {
            'queries': params.get('queries'),
            'include_connected_objects': params.get('include_connected_objects'),
            'connected_objects': params.get('connected_objects'),
            'sort_by': params.get('sort_by'),
            'sort_order': params.get('sort_order')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'POST', connector_info, config, data=json.dumps(payload))
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def execute_an_api_call(config, params, connector_info):
    try:
        endpoint = params.get("endpoint")
        http_method = params.get("method")
        query_params = params.get("query_params") if params.get("query_params") else None
        payload = json.dumps(params.get("payload")) if params.get("payload") else None
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, http_method, connector_info, config, params=query_params, data=payload)
        logger.debug("Response: {0}".format(response))
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
    'fetch_indicators': fetch_indicators,
    'get_reports': get_reports,
    'get_alerts': get_alerts,
    'search_collections': search_collections,
    'get_reputation_of_indicators': get_reputation_of_indicators,
    'execute_an_api_call': execute_an_api_call
}
