# pylint: disable=import-error
from VM_Orchestrator.settings import MONGO_INFO, settings

import pymongo
from slack import WebClient
from elasticsearch import Elasticsearch

ELASTIC_CLIENT = None
if settings['ELASTIC']['IP'] != '':
    ELASTIC_CLIENT = Elasticsearch([{'host':settings['ELASTIC']['IP'],'port':settings['ELASTIC']['PORT']}])
MONGO_CLIENT = pymongo.MongoClient(MONGO_INFO['CLIENT_URL'], connect=False)
INTERNAL_SLACK_WEB_CLIENT = WebClient(settings['SLACK']['INTERNAL_SLACK_KEY'])