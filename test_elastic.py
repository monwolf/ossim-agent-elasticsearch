import time
from elasticsearch import Elasticsearch
from elasticsearch.client import IndicesClient
import logging


class ElasticDetector(object):
    def __init__(self, es_host, plugin_name, rule_id, store_index='ossim_index'):
        self._es = Elasticsearch([es_host])
        self._store_index = store_index
        self.plugin_name = plugin_name
        self.rule_id = rule_id
        self._create_index()

    def _create_index(self):
        es_index = IndicesClient(self._es)
        if es_index.exists(self._store_index):
            logging.info('Index ' + self._store_index + ' already exists. Skipping index creation.')
            return None
        self._es.indices.create(self._store_index)

    def delete_store_index(self):
        self._es.indices.delete(index=self._store_index)

    def _insert_timestamp(self):

        current_timestamp = self._get_current_timestamp()
        logging.info("timestamp {}".format(current_timestamp))
        res = self._es.index(self._store_index, doc_type='last_runtime',
                             body={'@timestamp': self._get_current_timestamp(), 'plugin': self.plugin_name,
                                   'rule_id': self.rule_id})

    @staticmethod
    def _get_current_timestamp():
        ts_epoch = round(time.time() * 1000)
        return int(ts_epoch)

    def _get_last_timestamp(self):
        query = {
            "query": {
                "query_string": {
                    "query": "rule_id:{0} AND plugin:{1}".format(self.rule_id, self.plugin_name)
                }
            },
            "sort": {'@timestamp': {'order': 'desc'}}
        }
        res = self._es.search(index=self._store_index, body=query, size=1)
        hits = res['hits']['hits']

        logging.info("Got %d Hits:" % res['hits']['total'])
        for hit in res['hits']['hits']:
            logging.info(hit)

        if res['hits']['total'] > 0:
            return int(hits[0]['_source']['@timestamp'])
        else:
            return 0

    def _get_matches_since(self, data_index, timestamp, query):
        logging.debug('timestamp _get_matches_since: {}'.format(timestamp))
        query = {"query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "analyze_wildcard": True,
                            "query": query
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": timestamp,
                                "lte": self._get_current_timestamp(),
                                "format": "epoch_millis"
                            }
                        }
                    }
                ],
                "must_not": [

                ]
            }
        }
        }
        res = self._es.search(index=data_index, body=query)
        return res['hits']['hits']

    def do_something(self, data_index="*", query="*"):
        # self._insert_timestamp()
        timestamp = self._get_last_timestamp()
        documents = self._get_matches_since(data_index=data_index, timestamp=timestamp, query=query)
        logging.info("number of docs {}".format(len(documents)))
        # for doc in documents:
        # logging.info(doc)
        logging.info("timestamp {}".format(timestamp))


if __name__ == "__main__":
    url = 'http://aeaesclient01.globalia.com:9200'
    index = 'ossim_index'
    logging.getLogger().setLevel(logging.INFO)
    es = ElasticDetector(url, plugin_name='oauth', rule_id='9999', store_index=index)
    # es.delete_store_index()
    es.do_something("logstash-business-security-oauth-production-*",
                    "environment: production AND operation: token AND NOT trace.statusCode_int: 200")
