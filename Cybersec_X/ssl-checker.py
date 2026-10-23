import ssl
import socket
from datetime import datetime

def get_ssl_info(hostname):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cert = ssock.getpeercert()

                print("\n" + "=" * 60)
                print("SSL CERTIFICATE INSPECTOR")
                print("=" * 60)

                print(f"\nDomain: {hostname}")
                print(f"SSL Version: {ssock.version()}")

                # Subject
                subject = dict(x[0] for x in cert['subject'])
                print(f"\nCommon Name (CN): {subject.get('commonName', 'N/A')}")

                # Issuer
                issuer = dict(x[0] for x in cert['issuer'])
                print(f"Issuer: {issuer.get('commonName', 'N/A')}")

                # Serial Number
                print(f"Serial Number: {cert.get('serialNumber')}")

                # Expiry
                expiry = cert['notAfter']
                expiry_date = datetime.strptime(
                    expiry,
                    "%b %d %H:%M:%S %Y %Z"
                )

                remaining = (expiry_date - datetime.utcnow()).days

                print(f"\nValid Until: {expiry_date}")
                print(f"Days Remaining: {remaining}")

                if remaining < 0:
                    print("[!] Certificate EXPIRED")
                elif remaining < 30:
                    print("[!] Certificate expiring soon")
                else:
                    print("[OK] Certificate valid")

                # SAN
                print("\nSubject Alternative Names:")
                san = cert.get("subjectAltName", [])

                for item in san:
                    if item[0] == "DNS":
                        print(f"  - {item[1]}")

                print("\n" + "=" * 60)

    except ssl.SSLError as e:
        print(f"SSL Error: {e}")

    except socket.gaierror:
        print("Domain not found")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    domain = input("Enter domain (example.com): ").strip()
    get_ssl_info(domain)