from VM_Orchestrator.settings import MONGO_INFO
import pymongo

MONGO_CLIENT = pymongo.MongoClient(MONGO_INFO['CLIENT_URL'])