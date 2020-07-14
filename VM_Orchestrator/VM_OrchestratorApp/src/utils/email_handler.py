from django.core.mail import EmailMessage
from datetime import datetime
import json
import os
from VM_OrchestratorApp import settings

def send_email(file_dir, email_to, message, title):
	if not settings['EMAIL']['HOST_USER']:
		print("Couldn't seend email, email user not configurated")
		return
	email = EmailMessage(title, message, settings['EMAIL']['HOST_USER'], [email_to])
	email.attach_file(file_dir)
	email.send()
	print("An email has been send succesfully at:"+str(datetime.now()))

def send_notification_email(findings,email_to):
	if not settings['EMAIL']['HOST_USER']:
		print("Couldn't seend email, email user not configurated")
		return