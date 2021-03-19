"""Utility file to trigger unknown package ingestion."""

import logging
import os
from collections import namedtuple
from typing import Set
from requests_futures.sessions import FuturesSession

logger = logging.getLogger(__name__)

_INGESTION_API_URL = "http://{host}:{port}/{endpoint}".format(
    host=os.environ.get("INGESTION_SERVICE_HOST", "bayesian-jobs"),
    port=os.environ.get("INGESTION_SERVICE_PORT", "34000"),
    endpoint='internal/ingestions/epv')

_WORKERFLOW_API_URL = "http://{host}:{port}/{endpoint}".format(
    host=os.environ.get("INGESTION_SERVICE_HOST", "bayesian-jobs"),
    port=os.environ.get("INGESTION_SERVICE_PORT", "34000"),
    endpoint='internal/ingestions/trigger-workerflow')
_session = FuturesSession()
Package = namedtuple("Package", ["package", "version"])


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple]):
    """Unknown Package flow utility function.

    :param ecosystem: Ecosystem
    :param unknown_pkgs: Set of tuple having packages name and version
    """
    logger.debug('Triggered Unknown Package Flow for ecosystem: {} and Package: {}'
                 .format(ecosystem, unknown_pkgs))

    # Create payload to be passed to ingestion API
    payload = {
        "ecosystem": ecosystem,
        "packages": [],
        "force": False,
        "force_graph_sync": True,
        "source": "api"
    }

    # Set the unknown packages and versions
    for pkg in unknown_pkgs:
        # As API server and Backbone have different keys used.
        payload['packages'].append({'package': pkg.package, 'version': pkg.version})

    # If package list is not empty then call ingestion API
    if payload['packages']:
        try:
            _session.post(url=_INGESTION_API_URL, json=payload)
        except Exception as e:
            logger.error('Failed to trigger unknown flow for payload %s with error %s',
                         payload, e)
            raise Exception('Ingestion failed') from e
        else:
            logger.info('Ingestion call being executed')


def trigger_workerflow(payload):
    """Triggering workerflow utility function."""
    logger.debug("Triggered workerflow")

    try:
        _session.post(url=_WORKERFLOW_API_URL, json=payload)
    except Exception as e:
        logger.error('Failed to trigger unknown flow for payload %s with error %s',
                     payload, e)
        raise Exception('Ingestion failed') from e
    else:
        logger.info('Ingestion call being executed')
