from VM_OrchestratorApp import MONGO_CLIENT
from VM_Orchestrator.settings import MONGO_INFO

resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]


def add_vulnerability():
    
    return

# ------------------- RECON -------------------
def add_resource():
    resource = {
            'name': 'test_name'

        }
    # if is_alive == 'True':
    # slack_sender.send_new_domain_found_message(name, ip)
    resources.insert_one(resource)