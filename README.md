# VTScan

VTScan es una herramienta simple en Python para escanear archivos en VirusTotal y mostrar los resultados en la terminal.

## Requisitos

- Python 3.x
- Bibliotecas Python: `requests` (instalable con `pip install requests`)

## Uso

python3 vtscan.py <archivo>

Donde <archivo> es la ruta al archivo que deseas escanear.

## Configuración
Antes de utilizar la herramienta, asegúrate de configurar tu clave de API de VirusTotal en el script. Reemplaza el valor de API_KEY con tu propia clave.

API_KEY = "tu_clave_de_api"

## Ejemplo
python3 vtscan.py archivo.exe
