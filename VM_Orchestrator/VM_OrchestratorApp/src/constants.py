# pylint: disable=import-error
from VM_Orchestrator.settings import REDMINE_IDS
from VM_OrchestratorApp import tasks
"""
CONSTANTS.PY
"""

### LANGUAGES ###
LANGUAGE_ENGLISH = 'eng'
LANGUAGE_SPANISH = 'spa'

### GENERAL ###
BURP_SCAN = {
    'english_name': '[BURP SCAN] - ',
    'spanish_name': '[BURP SCAN] - ',
    'status' : REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'burp_module'
}

NESSUS_SCAN = {
    'english_name': '[NESSUS SCAN] - ',
    'spanish_name': '[NESSUS SCAN] - ',
    'status' : REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'ip',
    'module_identifier': 'nessus_module'
}

ACUNETIX_SCAN = {
    'english_name': '[ACUNETIX SCAN] - ',
    'spanish_name': '[ACUNETIX SCAN] - ',
    'status' : REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'ip',
    'module_identifier': 'acu_module'
}

### VULNERABILITIES ###
INVALID_VALUE_ON_HEADER = {
    'english_name': 'Insecure HTTP Response Header Configuration (Invalid value)',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status' : REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'header_module'
}
HEADER_NOT_FOUND = {
    'english_name': 'Insecure HTTP Response Header Configuration (Not found)',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'header_module'
}
HOST_HEADER_ATTACK = {
    'english_name': 'Host header attack possible',
    'spanish_name': 'Ataque de cabecera Host posible',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'hha_module'
}
UNSECURE_METHOD = {
    'english_name': 'Extended HTTP methods enabled',
    'spanish_name': 'Métodos HTTP extendidos habilitados',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'httpmethod_module'
}
SSL_TLS = {
    'english_name': 'Weak transport layer security (TLS) configuration',
    'spanish_name': 'Inadecuada configuración de seguridad de capa de transporte (TLS)',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'tls_module'
}
OUTDATED_3RD_LIBRARIES = {
    'english_name': 'Outdated 3rd party libraries in use',
    'spanish_name': 'Librerias 3rd party desactualizadas en uso',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'libraries_module'
}
CORS = {
    'english_name': 'CORS vulnerability found',
    'spanish_name': 'Se encontro una vulnerabilidad de CORS',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'cors_module'
}
ENDPOINT = {
    'english_name': 'Vulnerable endpoints were found',
    'spanish_name': 'Se encontraron endpoints vulnerables',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'ffuf_module'
}
BUCKET = {
    'english_name': 'Misconfiguration in Bucket found',
    'spanish_name': 'Mala configuración en Bucket',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'bucket_module'
}
TOKEN_SENSITIVE_INFO = {
    'english_name': 'Token information disclosure was found',
    'spanish_name': 'Token con informacion sensible encontrado',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'token_module'
}
CSS_INJECTION = {
    'english_name': 'Possible css injection found',
    'spanish_name': 'Posible inyeccion css',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'css_module'
}
OPEN_FIREBASE = {
    'english_name': 'Firebase found open',
    'spanish_name': 'Se encontro firebase abierta',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'firebase_module'
}
OUTDATED_SOFTWARE_NMAP = {
    'english_name': 'Outdated software in use',
    'spanish_name': 'Software desactualizado',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}
HTTP_PASSWD_NMAP = {
    'english_name': 'Path traversal found',
    'spanish_name': 'Path traversal encontrado',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}
WEB_VERSIONS_NMAP = {
    'english_name': 'Web versions vulnerabilities found',
    'spanish_name': 'Vulnerabilidades de versiones web encontradas',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}
ANON_ACCESS_FTP = {
    'english_name': 'Anonymous access to FTP server',
    'spanish_name': 'Permisos de escritura en servidor FTP en forma anónima',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}

CRED_ACCESS_FTP = {
    'english_name': 'Access to FTP server with default credentials',
    'spanish_name': 'Acceso a FTP con credenciales por defecto',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}
DEFAULT_CREDS = {
    'english_name': 'Default credentials in use',
    'spanish_name': 'Acceso administrativo mediante usuarios por defecto',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_script_module'
}
IIS_SHORTNAME_MICROSOFT = {
    'english_name': 'Microsoft short name directory and file enumeration',
    'spanish_name': 'Enumeración de nombres cortos de archivos y directorios de Microsoft',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'web',
    'module_identifier': 'iis_module'
}
POSSIBLE_ERROR_PAGES = {
    'english_name': 'Possible information disclosure within system error messages',
    'spanish_name': 'Posible inadecuado manejo de errores',
    'status': REDMINE_IDS['STATUS_NEW_VERIFY'],
    'scan_type': 'web',
    'module_identifier': 'nmap_script_module'
}
PLAINTEXT_COMUNICATION = {
    'english_name': 'Plaintext communication services',
    'spanish_name': 'Comunicación no cifrada',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_baseline_module'
}
UNNECESSARY_SERVICES = {
    'english_name': 'Unnecessary services exposed to the Internet',
    'spanish_name': 'Servicios innecesarios disponibles en internet',
    'status': REDMINE_IDS['STATUS_NEW'],
    'scan_type': 'ip',
    'module_identifier': 'nmap_baseline_module'
}