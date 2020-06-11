from VM_Orchestrator.settings import MONGO_INFO, settings

import pymongo
from slack import WebClient

MONGO_CLIENT = pymongo.MongoClient(MONGO_INFO['CLIENT_URL'])
SLACK_WEB_CLIENT = WebClient(settings['SLACK']['SLACK_KEY'])