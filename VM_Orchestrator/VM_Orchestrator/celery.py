from __future__ import absolute_import, unicode_literals

import os

from celery import Celery

from VM_OrchestratorApp import settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VM_Orchestrator.settings')

app = Celery('VM_Orchestrator', backend=settings['CELERY']['BROKER_URL'], broker=settings['CELERY']['BROKER_URL'])

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.conf.broker_transport_options = {'visibility_timeout': 86400}
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))