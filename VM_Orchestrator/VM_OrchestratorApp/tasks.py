from celery import shared_task
from celery.task import periodic_task
from celery.schedules import crontab

from datetime import datetime, date

from VM_OrchestratorApp.src.recon import initial_recon, aquatone
from VM_Orchestrator.settings import settings
import VM_OrchestratorApp.src.utils.mongo as mongo

# ------ RECON ------ #
@shared_task
def subdomain_recon_task(scan_info):
    initial_recon.run_recon(scan_info)
    return

@shared_task
def resolver_recon_task(scan_info):
    subdomains = mongo.get_subdomains_from_target(scan_info['target_name'])
    aquatone.start_aquatone(subdomains, scan_info)
    return


# ------ PERIODIC TASKS ------ #
#@periodic_task(run_every=crontab(day_of_month=settings['PROJECT']['START_DATE'].day, month_of_year=settings['PROJECT']['START_DATE'].month))
#def project_start_task():
#    today_date = datetime.combine(date.today(), datetime.min.time())
#    # This will make it so the tasks only runs once in the program existence
#    if(today_date.year != settings['PROJECT']['START_DATE'].year):
#       return

@periodic_task(run_every=crontab(hour=settings['PROJECT']['HOUR'], minute=settings['PROJECT']['MINUTE'], day_of_week=settings['PROJECT']['DAY_OF_WEEK']))
def recon_monitoring():
    # We first check if the project has started, we return if not
    today_date = datetime.combine(date.today(), datetime.min.time())
    if today_date < settings['PROJECT']['START_DATE']:
        return
    # We get every 'target'
    info_to_send = {
        'target_name': 'tesla.com',
        'is_first_run': False
    }
    subdomain_recon_task(info_to_send)
    resolver_recon_task(info_to_send)
    return