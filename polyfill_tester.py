import csv
import argparse
from requests_html import HTMLSession
from requests_html import HTMLResponse

# Configurar argparse para manejar argumentos de línea de comandos
parser = argparse.ArgumentParser(description="Verificar si sitios web son potencialmente vulnerables.")
parser.add_argument("input_file", help="Archivo de texto con la lista de URLs.")
args = parser.parse_args()

# Definir el archivo de salida
output_file = 'results.csv'

# Inicializar una sesión de requests_html con configuración para deshabilitar verificación de certificados SSL
session = HTMLSession()
session.verify = False  # Deshabilitar la verificación de certificados SSL

# Función para verificar si un sitio contiene el dominio polyfill.io
def is_vulnerable(url):
    try:
        response: HTMLResponse = session.get(url)
        response.html.render()  # Renderizar la página para ejecutar el JavaScript
        if 'polyfill.io' in response.html.html:
            return True
    except Exception as e:
        print(f"Error al acceder a {url}: {e}")
    return False

# Leer la lista de URLs del archivo de texto
with open(args.input_file, 'r') as file:
    urls = [line.strip() for line in file]

# Procesar cada URL y verificar si es vulnerable
results = []
for url in urls:
    print(f"Verificando {url}...")
    vulnerable = is_vulnerable(url)
    results.append([url, 'Sí' if vulnerable else 'No'])

# Guardar los resultados en un archivo CSV
with open(output_file, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['URL', 'Potencialmente Vulnerable'])
    csvwriter.writerows(results)

print(f"Resultados guardados en {output_file}")
