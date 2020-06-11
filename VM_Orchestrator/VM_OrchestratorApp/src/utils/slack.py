from VM_Orchestrator.settings import settings
from VM_OrchestratorApp import SLACK_WEB_CLIENT

def send_simple_message(message):
    try:
        SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['SLACK_CHANNEL'], text=str(message))
    except Exception:
        return
    return