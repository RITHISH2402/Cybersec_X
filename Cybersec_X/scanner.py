import requests
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options"
]

def check_security_headers(response):
    print("\n[+] Security Header Check")

    for header in SECURITY_HEADERS:
        if header in response.headers:
            print(f"[OK] {header} Present")
        else:
            print(f"[VULNERABLE] Missing {header}")

def check_directory_listing(response):
    print("\n[+] Directory Listing Check")

    indicators = [
        "Index of /",
        "Directory listing for",
        "Parent Directory"
    ]

    for indicator in indicators:
        if indicator.lower() in response.text.lower():
            print("[VULNERABLE] Directory Listing Enabled")
            return

    print("[OK] Directory Listing Not Detected")

def check_information_disclosure(response):
    print("\n[+] Information Disclosure Check")

    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")

    if server:
        print(f"[VULNERABLE] Server Header Exposed: {server}")
    else:
        print("[OK] Server Header Hidden")

    if powered_by:
        print(f"[VULNERABLE] X-Powered-By Exposed: {powered_by}")
    else:
        print("[OK] X-Powered-By Hidden")

def main():
    print("=" * 50)
    print("Simple Web Security Scanner")
    print("=" * 50)

    url = input("Enter Target URL (https://example.com): ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SimpleSecurityScanner/1.0"}
        )

        print(f"\nTarget: {url}")
        print(f"Status Code: {response.status_code}")

        check_security_headers(response)
        check_directory_listing(response)
        check_information_disclosure(response)

        print("\n[+] Scan Completed")

    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    main()