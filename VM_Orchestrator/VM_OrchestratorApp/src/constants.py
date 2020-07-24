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
    'status' : 11
}

NESSUS_SCAN = {
    'english_name': '[NESSUS SCAN] - ',
    'spanish_name': '[NESSUS SCAN] - ',
    'status' : 11
}

ACUNETIX_SCAN = {
    'english_name': '[ACUNETIX SCAN] - ',
    'spanish_name': '[ACUNETIX SCAN] - ',
    'status' : 11
}

### VULNERABILITIES ###
INVALID_VALUE_ON_HEADER = {
    'english_name': 'Insecure HTTP Response Header Configuration (Invalid value)',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status' : 7
}
HEADER_NOT_FOUND = {
    'english_name': 'Insecure HTTP Response Header Configuration (Not found)',
    'spanish_name': 'Inadecuada configuración de encabezados de seguridad',
    'status': 7
}
HOST_HEADER_ATTACK = {
    'english_name': 'Host header attack possible',
    'spanish_name': 'Ataque de cabecera Host posible',
    'status': 11
}
UNSECURE_METHOD = {
    'english_name': 'Extended HTTP methods enabled',
    'spanish_name': 'Métodos HTTP extendidos habilitados',
    'status': 11
}
SSL_TLS = {
    'english_name': 'Weak transport layer security (TLS) configuration',
    'spanish_name': 'Inadecuada configuración de seguridad de capa de transporte (TLS)',
    'status': 7
}
OUTDATED_3RD_LIBRARIES = {
    'english_name': 'Outdated 3rd party libraries in use',
    'spanish_name': 'Librerias 3rd party desactualizadas en uso',
    'status': 11
}
CORS = {
    'english_name': 'CORS vulnerability found',
    'spanish_name': 'Se encontro una vulnerabilidad de CORS',
    'status': 11
}
ENDPOINT = {
    'english_name': 'Vulnerable endpoints were found',
    'spanish_name': 'Se encontraron endpoints vulnerables',
    'status': 11
}
BUCKET = {
    'english_name': 'Misconfiguration in Bucket found',
    'spanish_name': 'Mala configuración en Bucket',
    'status': 7
}
TOKEN_SENSITIVE_INFO = {
    'english_name': 'Token information disclosure was found',
    'spanish_name': 'Token con informacion sensible encontrado',
    'status': 11
}
CSS_INJECTION = {
    'english_name': 'Possible css injection found',
    'spanish_name': 'Posible inyeccion css',
    'status': 11
}
OPEN_FIREBASE = {
    'english_name': 'Firebase found open',
    'spanish_name': 'Se encontro firebase abierta',
    'status': 7
}
OUTDATED_SOFTWARE_NMAP = {
    'english_name': 'Outdated software in use',
    'spanish_name': 'Software desactualizado',
    'status': 7
}
HTTP_PASSWD_NMAP = {
    'english_name': 'Path traversal found',
    'spanish_name': 'Path traversal encontrado',
    'status': 11
}
WEB_VERSIONS_NMAP = {
    'english_name': 'Web versions vulnerabilities found',
    'spanish_name': 'Vulnerabilidades de versiones web encontradas',
    'status': 7
}
ANON_ACCESS_FTP = {
    'english_name': 'Anonymous access to FTP server',
    'spanish_name': 'Permisos de escritura en servidor FTP en forma anónima',
    'status': 7
}
# TODO revisar spanish name
CRED_ACCESS_FTP = {
    'english_name': 'Access to FTP server with default credentials',
    'spanish_name': 'Acceso administrativo mediante usuarios por defecto',
    'status': 7
}
DEFAULT_CREDS = {
    'english_name': 'Default credentials in use',
    'spanish_name': 'Acceso administrativo mediante usuarios por defecto',
    'status': 7
}
IIS_SHORTNAME_MICROSOFT = {
    'english_name': 'Microsoft short name directory and file enumeration',
    'spanish_name': 'Enumeración de nombres cortos de archivos y directorios de Microsoft',
    'status': 7
}
POSSIBLE_ERROR_PAGES = {
    'english_name': 'Possible information disclosure within system error messages',
    'spanish_name': 'Posible inadecuado manejo de errores',
    'status': 11
}
PLAINTEXT_COMUNICATION = {
    'english_name': 'Plaintext communication services',
    'spanish_name': 'Comunicación no cifrada',
    'status': 7
}
UNNECESSARY_SERVICES = {
    'english_name': 'Unnecessary services exposed to the Internet',
    'spanish_name': 'Servicios innecesarios disponibles en internet',
    'status': 7
}