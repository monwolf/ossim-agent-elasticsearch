import time

from elasticsearch import Elasticsearch
from elasticsearch.client import IndicesClient
import logging


class ElasticDetector(object):
    def __init__(self, es_host, plugin_name, rule_id, store_index='ossim_index', verify_certs=True):
        if not verify_certs:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            urllib3.disable_warnings(UserWarning)

        self._es = Elasticsearch([es_host], verify_certs=verify_certs)
        self._store_index = store_index
        self.plugin_name = plugin_name
        self.rule_id = rule_id
        self._create_index()
        self._scroll_time = '10m'
        self._windows_size = 50

    def _create_index(self):
        es_index = IndicesClient(self._es)
        if es_index.exists(self._store_index):
            logging.info('Index ' + self._store_index + ' already exists. Skipping index creation.')
            return None
        self._es.indices.create(self._store_index)
        es_mapping = {'last_runtime':
            {
                'properties': {
                    'plugin': {'index': 'not_analyzed', 'type': 'string'},
                    'rule_id': {'index': 'not_analyzed', 'type': 'long'},
                    '@timestamp': {'format': 'dateOptionalTime||epoch_millis', 'type': 'date'}
                }
            }
        }

        self._es.indices.put_mapping(index=index, doc_type='last_runtime', body=es_mapping)

    def delete_store_index(self):
        self._es.indices.delete(index=self._store_index)

    def insert_timestamp(self):

        current_timestamp = self._get_current_timestamp()
        logging.info("timestamp {}".format(current_timestamp))
        self._es.index(self._store_index, doc_type='last_runtime',
                       body={'@timestamp': self._get_current_timestamp(), 'plugin': self.plugin_name,
                             'rule_id': self.rule_id})

    @staticmethod
    def _get_current_timestamp(offset_seconds=0):
        ts_epoch = round((time.time() + offset_seconds) * 1000)
        return int(ts_epoch)

    def get_last_timestamp(self):
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
            return self._get_current_timestamp(-3600)

    def get_matches_since(self, data_index, timestamp, query):
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
        import json
        logging.info(json.dumps(query))
        ds_count = self._windows_size
        skip = 0
        hits = []
        while ds_count == self._windows_size:
            res = self._es.search(index=data_index, body=query, size=self._windows_size, from_=skip)
            skip += self._windows_size
            ds_count = len(res['hits']['hits'])
            hits += res['hits']['hits']

        logging.info(json.dumps(hits))
        return hits

    def do_something(self, data_index="*", query="*", fields=None, timestamp=None):

        if not timestamp:
            timestamp = self.get_last_timestamp()

        documents = self.get_matches_since(data_index=data_index, timestamp=timestamp, query=query)
        for doc in documents:
            source = DotAccessibleDict(doc['_source'])
            group = []
            for field in fields:
                group.append(source[field])

            logging.info(group)
            break
        #self.insert_timestamp()
        logging.info("timestamp {}".format(timestamp))


class DotAccessibleDict(object):

    def __init__(self, data):
        self._data = data

    def __str__(self):
        return str(self._data)

    def __getitem__(self, name):
        val = self._data
        for key in name.split('.'):
            val = val[key]
        return val


if __name__ == "__main__":
    url = 'https://elastic.aireuropa.com'
    index = 'ossim_index'
    logging.getLogger().setLevel(logging.INFO)
    es = ElasticDetector(url, plugin_name='oauth', rule_id='9999', store_index=index, verify_certs=False)
    # es.delete_store_index()
    f = u"@timestamp,domain,geoip.ip,trace.parameters_object.username_string,host".split(',')
    print (f)
    # f = u"sort".split(',')
    es.do_something("logstash-business-security-oauth-production-*",
                    "environment: production AND operation: token AND NOT trace.statusCode_int: 200",
                    fields=f,
                    )
