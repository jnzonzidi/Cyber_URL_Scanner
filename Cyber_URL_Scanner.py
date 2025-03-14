#Written Jean NZONZIDI
import argparse
import validators
import requests
from urllib.parse import urlparse

def validate_url(url):
    if not validators.url(url):
        raise argparse.ArgumentTypeError("URL invalide")
    return url

def check_https(response):
    issues = []
    if not response.url.startswith('https://'):
        issues.append("Le site n'utilise pas HTTPS")
    return issues

def check_security_headers(response):
    security_headers = {
        'Strict-Transport-Security': 'Manque HSTS',
        'Content-Security-Policy': 'Politique de sécurité absente',
        'X-Content-Type-Options': 'Protection MIME manquante',
        'X-Frame-Options': 'Protection clickjacking manquante',
        'X-XSS-Protection': 'Protection XSS désactivée'
    }
    return [desc for header, desc in security_headers.items() if header not in response.headers]

def check_cookies(response):
    issues = []
    set_cookie = response.headers.get('Set-Cookie', '')
    for cookie in set_cookie.split(', '):
        parts = cookie.split('; ')
        if parts:
            name = parts[0].split('=')[0]
            if 'Secure' not in parts:
                issues.append(f"{name}: Secure flag manquant")
            if 'HttpOnly' not in parts:
                issues.append(f"{name}: HttpOnly flag manquant")
    return issues

def check_sensitive_files(base_url):
    sensitive_files = ['robots.txt', '.env', 'wp-config.php']
    found = []
    for file in sensitive_files:
        try:
            response = requests.get(f"{base_url}/{file}", timeout=5)
            if response.status_code == 200:
                found.append(file)
        except:
            pass
    return found

def main():
    parser = argparse.ArgumentParser(description="Cyber URL Scanner")
    parser.add_argument("url", type=validate_url, help="URL à analyser")
    args = parser.parse_args()

    try:
        response = requests.get(args.url, timeout=10)
    except requests.RequestException as e:
        print(f"Erreur de connexion: {e}")
        return

    base_url = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"
    
    report = {
        'https': check_https(response),
        'headers': check_security_headers(response),
        'cookies': check_cookies(response),
        'sensitive_files': check_sensitive_files(base_url),
        'server_info': response.headers.get('Server', 'Non spécifié')
    }

    print(f"\n🔍 Analyse de sécurité pour {response.url}\n")
    print("[+] Configuration Serveur:")
    print(f" - Serveur: {report['server_info']}")
    
    if report['https']:
        print("\n[!] Problèmes de sécurité:")
        for issue in report['https']:
            print(f" - {issue}")
    
    if report['headers']:
        print("\n[!] En-têtes de sécurité manquants:")
        for header in report['headers']:
            print(f" - {header}")
    
    if report['cookies']:
        print("\n[!] Problèmes de cookies:")
        for cookie in report['cookies']:
            print(f" - {cookie}")
    
    if report['sensitive_files']:
        print("\n[!] Fichiers sensibles détectés:")
        for file in report['sensitive_files']:
            print(f" - {file}")

    print("\n✅ Analyse terminée")

if __name__ == "__main__":
    main()