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

# Lista de dominios a verificar
domains_to_check = [
    'polyfill.io',
    'bootcdn.net',
    'bootcss.com',
    'staticfile.net',
    'staticfile.org',
    'unionadjs.com',
    'xhsbpza.com',
    'union.macoms.la',
    'newcrbpc.com'
]

def is_vulnerable(url):
    found_domains = []
    found_lines = []
    try:
        response: HTMLResponse = session.get(url)
        response.html.render(timeout=20)
        html_lines = response.html.html.splitlines()
        for line in html_lines:
            for domain in domains_to_check:
                if domain in line and domain not in found_domains:
                    found_domains.append(domain)
                    found_lines.append(line.strip())
    except Exception as e:
        print(f"{Fore.RED}Error al acceder a {url}: {e}{Style.RESET_ALL}")
    return found_domains, found_lines

with open(args.input_file, 'r') as file:
    urls = [line.strip() for line in file]

results = []
for url in urls:
    print(f"{Fore.YELLOW}Verificando {url}...{Style.RESET_ALL}")
    found_domains, found_lines = is_vulnerable(url)
    if found_domains:
        domains_str = ', '.join(found_domains)
        lines_str = '\n'.join(found_lines)
        print(f"{Fore.GREEN}URL: {url} es potencialmente vulnerable. Dominios encontrados: {domains_str}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Líneas de código vulnerables:\n{lines_str}{Style.RESET_ALL}")
        results.append([url, 'Si', domains_str])
    else:
        print(f"{Fore.CYAN}URL: {url} no es potencialmente vulnerable.{Style.RESET_ALL}")
        results.append([url, 'No', ''])

with open(output_file, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['URL', 'Potencialmente Vulnerable', 'Dominios Encontrados'])
    csvwriter.writerows(results)

print(f"{Fore.MAGENTA}Resultados guardados en {output_file}{Style.RESET_ALL}")
