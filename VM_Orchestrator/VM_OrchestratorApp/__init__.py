from VM_Orchestrator.settings import MONGO_INFO, settings

import pymongo
from slack import WebClient

MONGO_CLIENT = pymongo.MongoClient(MONGO_INFO['CLIENT_URL'], connect=False)
INTERNAL_SLACK_WEB_CLIENT = WebClient(settings['SLACK']['INTERNAL_SLACK_KEY'])
EXTERNAL_SLACK_WEB_CLIENT = WebClient(settings['SLACK']['EXTERNAL_SLACK_KEY'])