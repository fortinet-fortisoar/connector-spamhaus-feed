""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, datetime, time
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

MONTH_LIST = {
    'Jan': '-01-',
    'Feb': '-02-',
    'Mar': '-03-',
    'Apr': '-04-',
    'May': '-05-',
    'Jun': '-06-',
    'Jul': '-07-',
    'Aug': '-08-',
    'Sep': '-09-',
    'Oct': '-10-',
    'Nov': '-11-',
    'Dec': '-12-'
}

SERVICE = {
    "Don't Route Or Peer": "https://www.spamhaus.org/drop/drop.txt",
    "Extended Don't Route Or Peer": "https://www.spamhaus.org/drop/edrop.txt"
}


class SpamhausFeed(object):
    def __init__(self, config, *args, **kwargs):
        self.url = SERVICE.get(config.get('service'))
        self.sslVerify = config.get('verify_ssl')

    def make_rest_call(self, url, method):
        try:
            url = self.url
            response = requests.request(method, url, verify=self.sslVerify)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 404:
                return {'blocklist_ips': []}
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


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def fetch_datetime(ip_blacklist):
    for line in ip_blacklist[:6]:
        if 'Last-Modified' in line:
            x = line.split(",")[1].split(" ")
            date_time = x[3] + MONTH_LIST.get(x[2]) + x[1] + "T" + x[4] + ".000Z"
            last_modified = convert_datetime_to_epoch(date_time)
        elif 'Expires' in line:
            x = line.split(",")[1].split(" ")
            date_time = x[3] + MONTH_LIST.get(x[2]) + x[1] + "T" + x[4] + ".000Z"
            expires = convert_datetime_to_epoch(date_time)
            break
    return last_modified, expires


def fetch_indicators(config, params, **kwargs):
    sf = SpamhausFeed(config)
    endpoint = ""
    ip_blacklist_list = []
    response = sf.make_rest_call(endpoint, 'GET')
    if response:
        ip_blacklist = str(response).split("\\n")
        last_modified, expires = fetch_datetime(ip_blacklist)
        for ip in ip_blacklist[4:-1]:
            ip_type = ip.split(";")
            ip_blacklist_list.append(
                {'ip': ip_type[0].strip(), 'type': ip_type[1].strip(), 'last_modified': last_modified,
                 'expires': expires})
        return ip_blacklist_list


def _check_health(config):
    try:
        sf = SpamhausFeed(config)
        return True
    except Exception as err:
        raise ConnectorError('Invalid URL or Credentials')


operations = {
    'fetch_indicators': fetch_indicators
}
