rabbitmq-server &
(sleep 1m; rabbitmqctl add_user $USER $PASSWORD; rabbitmqctl set_user_tags $USER administrator; rabbitmqctl add_vhost $VHOST; rabbitmqctl set_permissions -p $VHOST $USER ".*" ".*" ".*") & 
(sleep 1m; (python3 manage.py runserver 0.0.0.0:3000 & celery -A VM_Orchestrator worker -B --loglevel=warning -f logfile -Q slow_queue,fast_queue,acunetix_queue,burp_queue))