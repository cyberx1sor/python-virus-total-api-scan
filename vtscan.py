import requests
import json
import sys
import hashlib
import urllib.parse

if len(sys.argv) != 2:
    print("Uso: python3 vtscan.py <archivo>")
    sys.exit(1)

archivo = sys.argv[1]

API_KEY = "82a0f957c81ad440d5899ade2b0e3eee3432128c89f70dc71d415adba3c64319"
url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': API_KEY}

with open(archivo, 'rb') as file:
    response = requests.post(url_scan, files={'file': file}, params=params)

json_response = json.loads(response.content)
scan_id = json_response['scan_id']

params['resource'] = json_response['sha256']
response = requests.get(url_report, params=params)

json_response = json.loads(response.content)
if json_response['response_code'] == 1:
    print(f"Escaneo completo: {json_response['verbose_msg']}\n")
    print(f"MD5: {json_response['md5']}")
    print(f"SHA-1: {json_response['sha1']}")
    print(f"SHA-256: {json_response['sha256']}\n")
    print("Resultados:")
    for scanner, result in json_response['scans'].items():
        if result['detected']:
            print(f"\033[91m{scanner}: Detectado\033[0m")
        else:
            print(f"{scanner}: No detectado")
        if result['result']:
            print(f"Resultado: {result['result']}")
        print(f"Actualizado el: {result['update']}\n")

    # Uso del SHA-256 directamente desde la respuesta para el enlace a VirusTotal
    print(f"Enlace al informe en VirusTotal: https://www.virustotal.com/gui/file/{json_response['sha256']}/details")
else:
    print("No se encontraron resultados para el archivo escaneado.")
