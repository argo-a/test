from flask import Flask, request, redirect, jsonify, session
import requests
import os
import logging
import hmac
import hashlib
import base64
from dotenv import load_dotenv
import json
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(32)  # for session management

# Configuration
SHOPIFY_API_KEY = os.getenv('SHOPIFY_API_KEY')
SHOPIFY_API_SECRET = os.getenv('SHOPIFY_API_SECRET')
DIMONA_API_TOKEN = os.getenv('DIMONA_API_TOKEN')
APP_URL = 'https://8705-50-90-12-236.ngrok-free.app'  # Your ngrok URL

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store tokens (in production, use a database)
store_tokens = {}

def verify_webhook(data, hmac_header):
    """Verify Shopify webhook signature"""
    digest = hmac.new(
        SHOPIFY_API_SECRET.encode('utf-8'),
        data,
        hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode('utf-8')
    return hmac.compare_digest(computed_hmac, hmac_header)

def verify_shopify_request():
    """Decorator to verify Shopify requests"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Verify the request is from Shopify
            shop_url = request.args.get('shop')
            if not shop_url:
                return 'Missing shop parameter', 400
            
            # Verify HMAC if present
            hmac_header = request.headers.get('X-Shopify-Hmac-Sha256')
            if hmac_header and request.get_data():
                if not verify_webhook(request.get_data(), hmac_header):
                    return 'Invalid signature', 401
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/install')
def install():
    """Initial app installation endpoint"""
    shop = request.args.get('shop')
    if not shop:
        return 'Missing shop parameter', 400

    # Construct the permission URL
    scopes = ['read_orders', 'write_orders']  # Add more scopes as needed
    redirect_uri = f"{APP_URL}/auth/callback"
    nonce = os.urandom(16).hex()
    
    # Store nonce in session
    session['nonce'] = nonce
    session['shop'] = shop
    
    install_url = f"https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}" \
                 f"&scope={'%20'.join(scopes)}&redirect_uri={redirect_uri}&state={nonce}"
    
    return redirect(install_url)

@app.route('/auth/callback')
def callback():
    """OAuth callback handler"""
    # Verify the state parameter
    if request.args.get('state') != session.get('nonce'):
        return 'Invalid state parameter', 400

    shop = session.get('shop')
    if not shop:
        return 'Missing shop parameter', 400

    # Exchange temporary code for permanent token
    access_token_url = f"https://{shop}/admin/oauth/access_token"
    
    response = requests.post(access_token_url, json={
        'client_id': SHOPIFY_API_KEY,
        'client_secret': SHOPIFY_API_SECRET,
        'code': request.args.get('code')
    })
    
    if response.status_code == 200:
        # Store the access token (in production, use a database)
        store_tokens[shop] = response.json()['access_token']
        
        # Create webhook for order creation
        create_order_webhook(shop, store_tokens[shop])
        
        return 'App successfully installed!'
    else:
        return f'Error getting access token: {response.text}', 400

def create_order_webhook(shop, access_token):
    """Create webhook for order creation"""
    headers = {
        'X-Shopify-Access-Token': access_token,
        'Content-Type': 'application/json'
    }
    
    webhook_data = {
        'webhook': {
            'topic': 'orders/create',
            'address': f"{APP_URL}/webhook/orders",
            'format': 'json'
        }
    }
    
    response = requests.post(
        f"https://{shop}/admin/api/2024-01/webhooks.json",
        json=webhook_data,
        headers=headers
    )
    
    if response.status_code == 201:
        logger.info(f"Successfully created webhook for {shop}")
    else:
        logger.error(f"Failed to create webhook: {response.text}")

def send_to_dimona(order_data):
    """Send order to Dimona API"""
    headers = {
        'Authorization': f'Bearer {DIMONA_API_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.post(
            "https://dimonatee.com/api/v2021/orders",
            json=order_data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending to Dimona: {e}")
        raise

@app.route('/webhook/orders', methods=['POST'])
@verify_shopify_request()
def order_webhook():
    """Handle incoming order webhooks"""
    try:
        shopify_order = request.json
        logger.info(f"Received order {shopify_order.get('order_number')} from {shopify_order.get('shop')}")
        
        # Transform order data
        dimona_order = {
            "id": str(shopify_order.get('order_number')),
            "sample": False,
            "reprint": False,
            "xqc": False,
            "address_to": {
                "address1": shopify_order.get('shipping_address', {}).get('address1', ''),
                "address2": shopify_order.get('shipping_address', {}).get('address2', ''),
                "city": shopify_order.get('shipping_address', {}).get('city', ''),
                "zip": shopify_order.get('shipping_address', {}).get('postal_code', ''),
                "country": shopify_order.get('shipping_address', {}).get('country_code', 'US'),
                "region": shopify_order.get('shipping_address', {}).get('province_code', ''),
                "first_name": shopify_order.get('shipping_address', {}).get('first_name', ''),
                "last_name": shopify_order.get('shipping_address', {}).get('last_name', '')
            },
            "address_from": {
                "address1": "1983 Tigertail Blvd",
                "address2": "",
                "city": "Dania",
                "zip": "33004",
                "country": "US",
                "region": "FL",
                "company": "Tee USA LLC"
            },
            "shipping": {
                "carrier": "USPS",
                "priority": "Standard"
            },
            "items": [{
                "id": item.get('id'),
                "sku": item.get('sku', ''),
                "preview_files": {
                    "front": next((
                        prop.get('value') for prop in item.get('properties', [])
                        if prop.get('name') == 'preview_url'
                    ), '')
                },
                "print_files": {
                    "front": next((
                        prop.get('value') for prop in item.get('properties', [])
                        if prop.get('name') == 'print_url'
                    ), '')
                },
                "quantity": item.get('quantity', 1)
            } for item in shopify_order.get('line_items', [])]
        }
        
        # Send to Dimona
        result = send_to_dimona(dimona_order)
        
        return jsonify({
            'status': 'success',
            'dimona_response': result
        })
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Use SSL in production!
    app.run(port=52097, debug=True)