# VM-Orchestrator

## Description

[Django](https://docs.djangoproject.com/en/3.0/) based application with [Celery](https://docs.celeryproject.org/en/stable/) backend task management.

VM-Orchestrator is a tool for facilitating project creation and management.

The idea is to automate all the steps we follow when a new project arrives, this includes:

* Scope recongnition based on a domain / ip
* Alerts when scope definition finishes, as well as notifications when new assets are found
* Self-monitoring projects. Scan periodicity can be set up which will allow scans to run whenever the user wants.
* Baseline vulnerability scans.
* Alerts when new vulnerabilities are found (Redmine, slack, etc).
* Dashboards that show the state of the project and assets

![Diagram](https://github.com/badBounty/VM-Orchestrator/blob/master/VM%20Orchestrator.png)


## Installation
Installation will begin with a plain Debian machine.  

We first install git  
`sudo apt-get install git`  

Clone repository with `--recurse-submodules`. We will be using other repositories in this project.  
`git clone https://github.com/badBounty/VM-Orchestrator.git --recurse-submodule`  

Now python  
`sudo apt-get install python3-pip`  
We like pipenv here but you can install with `pip3 install`  
`sudo pip3 install pipenv`  

We are going to install requirements for our project and subprojects  
`pipenv install -r requirements.txt`  
`pipenv install -r VM_Orchestrator/VM_OrchestratorApp/src/scanning/tools/CORScanner/requirements.txt`  
`pipenv install -r VM_Orchestrator/VM_OrchestratorApp/src/utils/tools/LinkFinder/requirements.txt`  

`sudo apt-get install dnsutils`  
`sudo apt-get install nmap`  

We will now install our rabbitMQ server (Our broker)  
`sudo apt-get install rabbitmq-server`  
`sudo rabbitmqctl add_user myuser pass` 
`sudo rabbitmqctl set_user_tags myuser mytag`
`sudo rabbitmqctl add_vhost myvhost`  
`sudo rabbitmqctl set_permissions -p myvhost myuser ".*" ".*" ".*"`  

We can start the server with
`sudo rabbitmq-server`

## Docker usage

### Presteps

1. Create docker containers for the following services:
    
    * MongoDB: Execute bash.sh file.
    * Elasticseach & Kibanna: Execute bash.sh file and after a few minutes execute Configure.sh file.
    * Redmine: Execute bash.sh file. 
    
    The resouces for this are in the VM_Orchestrator/Resources folder

2.  Create the settings.json file in the VM_Orchestrator folder. 

3.  Copy the content of settings-example.json into settings.json. You will have to modify some values in order to get the proper functionality. Consult which values you will need to modify. 

3.  Build the Dockerfile in this folder passing the following parameter.

    |Parameter | Description |
    |----------|-------------|
    |USER| The rabbitmq user|
    |PASSWORD| The rabbitmq password|
    |VHOST| The Virtual Host for rabbitmq|

    Command Example:
    ```
    docker build -t orchestrator --build-arg USER=username --build-arg PASSWORD=password --build-arg VHOST=orchestrator .
    ```
    Note: In the build-arg parameters you will need to provide the values of rabbitmq (user, password, host).

4.  Run the image publishing the container's 3000 port in any free port.

    Command Example:
    ```
    docker run --name orchestrator -p 4000:3000 -v PathToMySettings.json:/VM-Orchestrator-project/VM-Orchestrator/VM_Orchestrator/settings.json -d orchestrator
    ```
    Note: PathToMySettings.json refers to the path in which your host's settings.json is allocated.
