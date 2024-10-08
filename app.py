from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
import socket

app = Flask(__name__)


SECURITYTRAILS_API_KEY = 'l0QGaJUvyL3JvJdwWNK03uZAsiRNV3gI'

IPGEOLOCATION_API_KEY = '484c571ff0c44f22838a597e3f493931'

IPDATA_API_KEY = '0f417adefe8998cd790bc808b51e7a1e0e57b5870723177a4c31f55b'

@app.route('/')
def analyze_website():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400

    domain_info = get_domain_info(url)
    subdomains = get_subdomains(url)
    asset_domains = get_external_assets(url)

    result = {
        "info": domain_info,
        "subdomains": subdomains,
        "asset_domains": asset_domains
    }

    return jsonify(result)

def get_domain_info(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        ipv4 = get_ip(domain, socket.AF_INET)
        ipv6 = get_ip(domain, socket.AF_INET6)

        ipv4_info = get_ip_info(ipv4)
        ipv6_info = get_ip_info(ipv6)

        return {
            "ipv4": ipv4_info,
            "ipv6": ipv6_info
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip(domain, family):
    try:
        addr_info = socket.getaddrinfo(domain, None, family)
        ip_addresses = [addr[4][0] for addr in addr_info]
        return ip_addresses[0] if ip_addresses else None
    except Exception as e:
        return None

def get_ip_info(ip):
    try:
        if not ip:
            return None

        ipgeolocation_response = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={IPGEOLOCATION_API_KEY}&ip={ip}')
        ipgeolocation_data = ipgeolocation_response.json()

        ipdata_response = requests.get(f'https://api.ipdata.co/{ip}?api-key={IPDATA_API_KEY}')
        ipdata_asn = ipdata_response.json().get('asn', {})

        return {
            "ip": ipgeolocation_data.get('ip'),
            "isp": ipgeolocation_data.get('isp'),
            "organization": ipgeolocation_data.get('organization'),
            "asn": {
                "asn": ipdata_asn.get('asn'),
                "name": ipdata_asn.get('name'),
                "domain": ipdata_asn.get('domain'),
                "route": ipdata_asn.get('route'),
                "type": ipdata_asn.get('type')
            },
            "location": ipgeolocation_data.get('country_name')
        }
    except Exception as e:
        return {"error": str(e)}

def get_subdomains(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        headers = {'APIKEY': SECURITYTRAILS_API_KEY}
        response = requests.get(f'https://api.securitytrails.com/v1/domain/{domain}/subdomains', headers=headers)
        data = response.json()
        return data.get('subdomains', [])
    except Exception as e:
        return {"error": str(e)}

def get_external_assets(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            assets = {
                "javascripts": extract_js_urls(response.text),
                "stylesheets": extract_css_urls(response.text),
                "images": extract_image_urls(response.text),
                "iframes": extract_iframe_urls(response.text),
                "anchors": extract_anchor_urls(response.text)
            }
            return assets
        else:
            return {"error": f"Failed to fetch URL: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def extract_js_urls(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        script_tags = soup.find_all('script', src=True)
        js_urls = [tag['src'] for tag in script_tags if tag.get('src')]
        return js_urls
    except Exception as e:
        return []

def extract_css_urls(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        link_tags = soup.find_all('link', rel='stylesheet')
        css_urls = [tag['href'] for tag in link_tags if tag.get('href')]
        return css_urls
    except Exception as e:
        return []

def extract_image_urls(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        img_tags = soup.find_all('img', src=True)
        image_urls = [tag['src'] for tag in img_tags if tag.get('src')]
        return image_urls
    except Exception as e:
        return []

def extract_iframe_urls(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        iframe_tags = soup.find_all('iframe', src=True)
        iframe_urls = [tag['src'] for tag in iframe_tags if tag.get('src')]
        return iframe_urls
    except Exception as e:
        return []

def extract_anchor_urls(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        a_tags = soup.find_all('a', href=True)
        anchor_urls = [tag['href'] for tag in a_tags if tag.get('href')]
        return anchor_urls
    except Exception as e:
        return []

if __name__ == '__main__':
    app.run(debug=True)
