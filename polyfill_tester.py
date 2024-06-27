import csv
import argparse
import warnings
from requests_html import HTMLSession, HTMLResponse
from colorama import Fore, Style
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter('ignore', InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Verificar sitios web que son potencialmente vulnerables.")
parser.add_argument("input_file", help="Archivo de texto con la lista de URLs.")
args = parser.parse_args()

output_file = 'results.csv'

session = HTMLSession()
session.verify = False

def is_vulnerable(url):
    try:
        response: HTMLResponse = session.get(url)
        response.html.render(timeout=20)
        html_lines = response.html.html.splitlines()
        for line in html_lines:
            if 'polyfill.io' in line:
                return True, line.strip()
    except Exception as e:
        print(f"{Fore.RED}Error al acceder a {url}: {e}{Style.RESET_ALL}")
    return False, None

with open(args.input_file, 'r') as file:
    urls = [line.strip() for line in file]

results = []
for url in urls:
    print(f"{Fore.YELLOW}Verificando {url}...{Style.RESET_ALL}")
    vulnerable, line_content = is_vulnerable(url)
    if vulnerable:
        print(f"{Fore.GREEN}URL: {url} es potencialmente vulnerable. Contenido: {line_content}{Style.RESET_ALL}")
        results.append([url, 'Sí'])
    else:
        print(f"{Fore.CYAN}URL: {url} no es potencialmente vulnerable.{Style.RESET_ALL}")
        results.append([url, 'No'])

with open(output_file, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['URL', 'Potencialmente Vulnerable'])
    csvwriter.writerows(results)

print(f"{Fore.MAGENTA}Resultados guardados en {output_file}{Style.RESET_ALL}")
