from time import sleep

#
# LOCAL IMPORTS
#
from Detector import Detector
from Logger import Lazyformat
from ElasticDetector import ElasticDetector, DotAccessibleDict
from Event import Event


class ParserElastic(Detector):

    def __init__(self, conf, plugin, conn):
        self._conf = conf  # config.cfg info
        self._plugin = plugin  # plugins/X.cfg info
        self.rules = []  # list of RuleMatch objects
        self.conn = conn
        self.stop_processing = False
        self.sleep_time = 10
        Detector.__init__(self, conf, plugin, conn)
        self.loginfo(Lazyformat("Init ParserElastic"))

    def _fetch(self, document, fields):
        group = []
        for field in fields:
            try:
                group.append(document[field])
            except KeyError:
                group.append("")
                self.logwarn("{} doesn't exists in document {}".format(field, document))
        return group

    def process(self):
        self.loginfo(Lazyformat("Starting process ParserElastic"))

        elastic_url = self._plugin.get("config", "elastic_url")
        store_index = self._plugin.get("config", "store_index")
        data_index = self._plugin.get("config", "data_index")
        str_verify_certs = self._plugin.get("config", "verify_certs")
        verify_certs = True
        if str_verify_certs.lower() == "no":
            verify_certs = False
        name = self._plugin.get("config", "name")
        plugin_id = self._plugin.get("DEFAULT", "plugin_id")

        rules = self._plugin.rules()
        query = rules['query']['query']
        fields = rules['query']['fields'].split(',')
        es = ElasticDetector(elastic_url, plugin_name=name, rule_id=plugin_id, store_index=store_index,
                             verify_certs=verify_certs)
        while not self.stop_processing:
            try:
                timestamp = es.get_last_timestamp()
                self.loginfo(Lazyformat("Getting last documents since {}".format(timestamp)))
                documents = es.get_matches_since(data_index=data_index, timestamp=timestamp, query=query)
                for doc in documents:
                    wdoc = DotAccessibleDict(doc['_source'])
                    self.loginfo(wdoc)
                    group = self._fetch(wdoc, fields)
                    self.generate(group)
                es.insert_timestamp()
            except Exception, ex:
                self.logerror(Lazyformat("Elasticsearch operation to {} failed: {}", elastic_url, ex))
            sleep(float(self.sleep_time))

        self.loginfo(Lazyformat("Exiting process()"))

    def stop(self):
        self.logdebug(Lazyformat("Scheduling plugin stop"))
        self.stop_processing = True
        try:
            self.join(1)
        except RuntimeError:
            self.logwarn(Lazyformat("Stopping thread that likely hasn't started"))

    def generate(self, groups):
        self.logwarn(Lazyformat(groups))
        event = Event()
        rules = self._plugin.rules()
        for key, value in rules['query'].iteritems():
            if key != "query" and key != "regexp" and key != "fields":
                data = self._plugin.get_replace_array_value(value.encode('utf-8'), groups)
                if data is not None:
                    event[key] = data
        if event is not None:
            self.send_message(event)
