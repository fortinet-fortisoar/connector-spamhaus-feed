""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError, Connector
from .operations import operations, _check_health

logger = get_logger('spamhaus-feed')


class SpamhausFeed(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            logger.info('Executing action {}'.format)
            return action(config, params)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def check_health(self, config):
        _check_health(config)
