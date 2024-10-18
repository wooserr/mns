import requests
import ssl
import socket
from datetime import datetime
from colorama import Fore, Style, init


init(autoreset=True)

def detect_waf(url):
    waf_headers = [
        "cloudflare", "cf-ray", "cf-cache-status", 
        "x-amz-cf-id", "x-amz-apigw-id",
        "akamai-x-cache", "akamai-cloudlet", "akamai-ghost-ip",
        "x-iinfo", "incap-ses", "visid_incap",
        "x-sucuri-id", "x-sucuri-cache",
        "x-hw", "x-waf-status", "bigip-server",
        "bnsv", "barra-counter", "barracuda-ngfw",
        "sessioncookie", "WAF", "DenyAll",
        "fortiwafsid", "fortiweb",
        "cisco-asa",
        "modsecurity", "x-waf",
        "ec-range", "edgecast",
        "rbzid", "reblaze-proxy",
        "x-citrix-waf", "ns_af",
        "x-served-by", "x-cache", "x-fastly-request-id",
        "sp-waf", "sprequestguid",
        "blazingfast",
        "jsluid",  
        "safedog",
        "nsfocus",
        "powercdn"
    ]
    waf_detected = False

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    test_payload = "' OR 1=1 --"
    test_url = f"{url}{test_payload}"
    
    try:
        response = requests.get(test_url, headers=headers)
        for header in response.headers.values():
            for waf_header in waf_headers:
                if waf_header in header.lower():
                    waf_detected = True
                    print(f"{Fore.YELLOW}WAF algılandı: {waf_header.capitalize()}")
                    return True
        if response.status_code == 403 or "waf" in response.text.lower() or "firewall" in response.text.lower():
            waf_detected = True
            print(f"{Fore.YELLOW}Yanıt durumuna veya içeriğine göre WAF algılandı.")
            return True
    except requests.RequestException as e:
        print(f"{Fore.RED}WAF testi sırasında hata: {e}")
    
    if not waf_detected:
        print(f"{Fore.GREEN}WAF tespit edilmedi.")
        return False

def test_sql_injection(url):
    payloads = ["'", "' OR 1=1 --", "' OR 'a'='a"]
    vulnerable = False

    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                vulnerable = True
                print(f"{Fore.RED}SQL açığı mevcut: {payload}")
                break
        except requests.RequestException as e:
            print(f"{Fore.RED}SQL testi sırasında hata: {url}: {e}")
    
    if not vulnerable:
        print(f"{Fore.GREEN}SQL güvenlik açığı bulunamadı.")

def test_xss(url):
    payloads = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']
    vulnerable = False

    for payload in payloads:
        params = {'input': payload}
        try:
            response = requests.get(url, params=params)
            if payload in response.text:
                vulnerable = True
                print(f"{Fore.RED}XSS açığı mevcut: {payload}")
                break
        except requests.RequestException as e:
            print(f"{Fore.RED}XSS testi sırasında hata: {url}: {e}")
    
    if not vulnerable:
        print(f"{Fore.GREEN}XSS güvenlik açığı bulunamadı.")

def ssl_scan(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = cert['notBefore']
                not_after = cert['notAfter']

                print(f"\n{Fore.CYAN}SSL Sertifika Bilgileri:")
                print(f"{Fore.WHITE}  Başlık: {subject}")
                print(f"{Fore.WHITE}  Sağlayıcı: {issuer}")
                print(f"{Fore.WHITE}  Sürüm: {cert.get('version', 'Unknown')}")
                print(f"{Fore.WHITE}  Doğrulanılan tarih: {not_before}")
                print(f"{Fore.WHITE}  Geçerlilik Tarihi: {not_after}")
                print(f"{Fore.WHITE}  Seri Numarası: {cert['serialNumber']}")
                print(f"{Fore.WHITE}  İmza Algoritması: {cert.get('signatureAlgorithm', 'Unknown')}")

                not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after_date - datetime.utcnow()).days
                print(f"{Fore.WHITE}  Sertifikanın bitmesine kalan gün: {days_left} gün")

    except Exception as e:
        print(f"{Fore.RED}SSL taraması sırasında hata oluştu: {e}")

def main():
    url = input(f"{Fore.CYAN}Website URL'sini giriniz: ")
    
    hostname = url.split("://")[-1].split("/")[0]

    
    waf_choice = input(f"{Fore.YELLOW}WAF taraması yapmak istiyor musunuz? (evet/hayır): ").lower()
    if waf_choice == 'evet':
        print(f"{Fore.CYAN}WAF kontrol ediliyor (Firewall)...")
        if detect_waf(url):
            print(f"{Fore.YELLOW}Firewall algılandı, ileri kontroller atlanıyor...")
            return

   
    ssl_choice = input(f"{Fore.YELLOW}SSL sertifikası taraması yapmak istiyor musunuz? (evet/hayır): ").lower()
    if ssl_choice == 'evet':
        print(f"{Fore.CYAN}SSL sertifikası kontrol ediliyor...")
        ssl_scan(hostname)

   
    print(f"{Fore.YELLOW}Yöntem seçin:")
    print(f"{Fore.CYAN}1. SQL Injection")
    print(f"{Fore.CYAN}2. XSS")
    choice = input(f"{Fore.CYAN}SQL için 1, XSS için 2'yi tuşlayınız: ")

    if choice == "1":
        print(f"{Fore.CYAN}SQL güvenlik açıkları test ediliyor...")
        test_sql_injection(url)
    elif choice == "2":
        print(f"{Fore.CYAN}XSS güvenlik açıkları test ediliyor...")
        test_xss(url)
    else:
        print(f"{Fore.RED}Geçersiz seçim. Lütfen 1 veya 2'yi seçin.")

if __name__ == "__main__":
    main()
