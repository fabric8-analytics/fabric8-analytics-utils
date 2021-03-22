"""Tests for classes from ingestion_utils module."""

from f8a_utils.ingestion_utils import unknown_package_flow, \
    Package
import unittest
from unittest import mock
from f8a_utils.ingestion_utils import trigger_workerflow

# Input data
data_v1 = set()
data_v1.add(Package(package='pkg', version='ver'))


data_v2 = {
            "external_request_id": "ccddf6b7-34a7-4927-a273-146b17b6b1f7",
            "flowname": "componentApiFlow",
            "data": {
                "api_name": "component_analyses_post",
                "manifest_hash": "sadasdsfsdf4545dsfdsfdfdgffds",
                "ecosystem": "pypi",
                "packages_list": {
                    'name': "ejs",
                    'given_name': "ejs",
                    'version': "1.0.0"
                },
                "user_id": "ccddf6b7-34a7-4927-a273-146b17b6b1f7",
                "user_agent": "unit-test",
                "source": "unit-test",
                "telemetry_id": "ccddf6b7-34a7-4927-a273-146b17b6b1f7"
            }
        }


class MyTestCase(unittest.TestCase):
    """Test class for unknown_package_flow."""

    @mock.patch('requests_futures.sessions.FuturesSession.post')
    def test_ingest_epv(self, _session):
        """Test unknown_package_flow positive."""
        unknown_package_flow('dummy_eco', data_v1)

    @mock.patch('requests_futures.sessions.FuturesSession.post')
    def test_ingest_epv_failed(self, _session):
        """Test unknown_package_flow negative."""
        _session.side_effect = Exception(mock.Mock(return_value={'status': 404}), 'not found')
        with self.assertRaises(Exception):
            unknown_package_flow('dummy_eco', data_v1)

    @mock.patch('requests_futures.sessions.FuturesSession.post')
    def test_trigger_workerflow(self, _session):
        """Test worker flow positive."""
        trigger_workerflow(data_v2)

    @mock.patch('requests_futures.sessions.FuturesSession.post')
    def test_trigger_workerflow_failed(self, _session):
        """Test worker flow negative."""
        _session.side_effect = Exception(mock.Mock(return_value={'status': 404}), 'not found')
        with self.assertRaises(Exception):
            trigger_workerflow(data_v2)
