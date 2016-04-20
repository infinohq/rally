import datetime
from unittest import TestCase
import unittest.mock as mock

from esrally import config, metrics


class MockClientFactory:
    def __init__(self, config):
        self._es = mock.create_autospec(metrics.EsClient)

    def create(self):
        return self._es


class DummyIndexTemplateProvider:
    def __init__(self, config):
        pass

    def template(self):
        return "test-template"


class StaticClock:
    NOW = 1453362707

    @staticmethod
    def now():
        return StaticClock.NOW

    @staticmethod
    def stop_watch():
        return StaticStopWatch()


class StaticStopWatch:
    def start(self):
        pass

    def stop(self):
        pass

    def split_time(self):
        return 0

    def total_time(self):
        return 0


class MetricsTests(TestCase):
    TRIAL_TIMESTAMP = datetime.datetime(2016, 1, 31)

    def setUp(self):
        self.cfg = config.Config()
        self.cfg.add(config.Scope.application, "system", "env.name", "unittest")
        self.metrics_store = metrics.EsMetricsStore(self.cfg,
                                                    client_factory_class=MockClientFactory,
                                                    index_template_provider_class=DummyIndexTemplateProvider,
                                                    clock=StaticClock)
        # get hold of the mocked client...
        self.es_mock = self.metrics_store._client
        self.es_mock.exists.return_value = False

    def test_put_value_without_meta_info(self):
        throughput = 5000
        self.metrics_store.open(MetricsTests.TRIAL_TIMESTAMP, "test", "defaults", create=True)

        self.metrics_store.put_count_cluster_level("indexing_throughput", throughput, "docs/s")
        expected_doc = {
            "@timestamp": StaticClock.NOW * 1000,
            "trial-timestamp": "20160131T000000Z",
            "relative-time": 0,
            "environment": "unittest",
            "sample-type": "normal",
            "track": "test",
            "track-setup": "defaults",
            "name": "indexing_throughput",
            "value": throughput,
            "unit": "docs/s",
            "meta": {}
        }
        self.metrics_store.close()
        self.es_mock.exists.assert_called_with(index="rally-2016")
        self.es_mock.create_index.assert_called_with(index="rally-2016")
        self.es_mock.bulk_index.assert_called_with(index="rally-2016", doc_type="metrics", items=[expected_doc])

    def test_put_value_with_meta_info(self):
        throughput = 5000
        # add a user-defined tag
        self.cfg.add(config.Scope.application, "system", "user.tag", "intention:testing")
        self.metrics_store.open(MetricsTests.TRIAL_TIMESTAMP, "test", "defaults", create=True)

        # Ensure we also merge in cluster level meta info
        self.metrics_store.add_meta_info(metrics.MetaInfoScope.cluster, None, "source_revision", "abc123")
        self.metrics_store.add_meta_info(metrics.MetaInfoScope.node, "node0", "os_name", "Darwin")
        self.metrics_store.add_meta_info(metrics.MetaInfoScope.node, "node0", "os_version", "15.4.0")
        # Ensure we separate node level info by node
        self.metrics_store.add_meta_info(metrics.MetaInfoScope.node, "node1", "os_name", "Linux")
        self.metrics_store.add_meta_info(metrics.MetaInfoScope.node, "node1", "os_version", "4.2.0-18-generic")

        self.metrics_store.put_value_node_level("node0", "indexing_throughput", throughput, "docs/s")
        expected_doc = {
            "@timestamp": StaticClock.NOW * 1000,
            "trial-timestamp": "20160131T000000Z",
            "relative-time": 0,
            "environment": "unittest",
            "sample-type": "normal",
            "track": "test",
            "track-setup": "defaults",
            "name": "indexing_throughput",
            "value": throughput,
            "unit": "docs/s",
            "meta": {
                "tag_intention": "testing",
                "source_revision": "abc123",
                "os_name": "Darwin",
                "os_version": "15.4.0"
            }
        }
        self.metrics_store.close()
        self.es_mock.exists.assert_called_with(index="rally-2016")
        self.es_mock.create_index.assert_called_with(index="rally-2016")
        self.es_mock.bulk_index.assert_called_with(index="rally-2016", doc_type="metrics", items=[expected_doc])

    def test_get_value(self):
        throughput = 5000
        search_result = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "value": throughput
                        }
                    }
                ]
            }
        }
        self.es_mock.search = mock.MagicMock(return_value=search_result)

        self.metrics_store.open(MetricsTests.TRIAL_TIMESTAMP, "test", "defaults")

        expected_query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "term": {
                                "trial-timestamp": "20160131T000000Z"
                            }
                        },
                        {
                            "term": {
                                "environment": "unittest"
                            }
                        },
                        {
                            "term": {
                                "track": "test"
                            }
                        },
                        {
                            "term": {
                                "track-setup": "defaults"
                            }
                        },
                        {
                            "term": {
                                "name": "indexing_throughput"
                            }
                        }
                    ]
                }
            }
        }

        actual_throughput = self.metrics_store.get_one("indexing_throughput")

        self.es_mock.search.assert_called_with(index="rally-2016", doc_type="metrics", body=expected_query)

        self.assertEqual(throughput, actual_throughput)
