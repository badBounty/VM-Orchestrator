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

This is a work in progress
