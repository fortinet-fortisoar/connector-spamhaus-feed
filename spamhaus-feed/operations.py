""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json, datetime, time
from connectors.core.connector import get_logger, ConnectorError

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('spamhaus-feed')

errors = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error'
}


class SpamhausFeed(object):
    def __init__(self, config, *args, **kwargs):
        self.username = config.get('username')
        self.password = config.get('password')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url)
        else:
            self.url = url + '/'
        self.token = self.login(self.url, self.username, self.password)
        self.sslVerify = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token}
            response = requests.request(method, url, headers=headers, verify=self.sslVerify, data=data, params=params)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 404:
                return {'results': []}
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
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

    def login(self, url, username, password):
        body = {
                'username': username,
                'password': password,
                'realm': 'intel'
        }
        endpoint = url + 'api/v1/login'
        try:
            response = requests.post(endpoint, data=json.dumps(body))
            if response:
                return response.json().get('token')
            else:
                raise ConnectorError("Invalid endpoint or credentials")
        except Exception as err:
            logger.exception("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))


def check_payload(payload):
    payload1 = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                payload1[key] = nested
        elif value:
            payload1[key] = value
    return payload1


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def fetch_indicators(config, params, **kwargs):
    try:
        sf = SpamhausFeed(config)
        endpoint = "api/intel/v1/byobject/cidr/{0}/{1}/{2}/{3}".format(params.get('dataset'),
                                                                       params.get('mode').lower(),
                                                                       params.get('type').lower(),
                                                                       params.get('ipaddress'))
        start_time = params.get('start_time')
        if start_time:
            start_time = convert_datetime_to_epoch(start_time)
        end_time = params.get('end_time')
        if end_time:
            end_time = convert_datetime_to_epoch(end_time)
        payload = {
            'limit': params.get('limit'),
            'since': start_time,
            'until': end_time
        }
        payload = check_payload(payload)
        response = sf.make_rest_call(endpoint, 'GET', params=payload)
        response = response.get('results')
        try:
            mode = params.get('output_mode')
            if mode == 'Create as Feed Records in FortiSOAR':
                create_pb_id = params.get("create_pb_id")
                trigger_ingest_playbook(response, create_pb_id, parent_env=kwargs.get('env', {}),
                                        batch_size=1000, dedup_field="pattern")
                return {"message": "Succesfully triggered playbooks for creating feed records"}
            else:
                return response
        except Exception as e:
            logger.exception("Import Failed")
            raise ConnectorError('Ingestion Failed with error: ' + str(e))
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        sf = SpamhausFeed(config)
        return True
    except Exception as err:
        raise ConnectorError('Invalid URL or Credentials')


operations = {
    'fetch_indicators': fetch_indicators
}
