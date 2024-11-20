from flask import Flask, request, redirect, jsonify, session
import requests
import os
import logging
import hmac
import hashlib
import base64
from dotenv import load_dotenv
import json
from datetime import datetime

# Load environment variables
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(32)  # for session management

def create_metafield_definitions(shop_url, access_token):
    """Create product metafield definitions in Shopify"""
    headers = {
        'X-Shopify-Access-Token': access_token,
        'Content-Type': 'application/json'
    }

    query = """
    mutation CreateMetafieldDefinitions {
      productMetafieldDefinitionCreate(
        definition: {
          name: "Front Print Files"
          namespace: "custom"
          key: "print_files"
          type: "single_line_text_field"
          description: "Front print files for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
      
      frontPreviewDefinition: productMetafieldDefinitionCreate(
        definition: {
          name: "Front Preview File"
          namespace: "custom"
          key: "front_preview_file"
          type: "single_line_text_field"
          description: "Front preview file for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
      
      backPreviewDefinition: productMetafieldDefinitionCreate(
        definition: {
          name: "Back Preview File"
          namespace: "custom"
          key: "back_preview_file"
          type: "single_line_text_field"
          description: "Back preview file for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
      
      backPrintDefinition: productMetafieldDefinitionCreate(
        definition: {
          name: "Back Print Files"
          namespace: "custom"
          key: "back_print_files"
          type: "single_line_text_field"
          description: "Back print files for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
      
      neckPrintDefinition: productMetafieldDefinitionCreate(
        definition: {
          name: "Neck Print Files"
          namespace: "custom"
          key: "neck_print_files"
          type: "single_line_text_field"
          description: "Neck print files for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
      
      neckPreviewDefinition: productMetafieldDefinitionCreate(
        definition: {
          name: "Neck Preview File"
          namespace: "custom"
          key: "neck_preview_file"
          type: "single_line_text_field"
          description: "Neck preview file for product"
        }
      ) {
        createdDefinition {
          id
        }
        userErrors {
          field
          message
        }
      }
    }
    """
    
    try:
        response = requests.post(
            f"https://{shop_url}/admin/api/2024-01/graphql.json",
            headers=headers,
            json={'query': query}
        )
        
        response.raise_for_status()
        result = response.json()
        
        logger.info(f"Metafield definitions creation result: {json.dumps(result, indent=2)}")
        return result
        
    except Exception as e:
        logger.error(f"Error creating metafield definitions: {str(e)}")
        raise

def verify_webhook(data, hmac_header):
    """Verify Shopify webhook signature"""
    digest = hmac.new(
        os.getenv('SHOPIFY_API_SECRET').encode('utf-8'),
        data,
        hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode('utf-8')
    return hmac.compare_digest(computed_hmac, hmac_header)

@app.route('/install')
def install():
    """Initial app installation endpoint"""
    shop = request.args.get('shop')
    if not shop:
        return 'Missing shop parameter', 400

    # Construct the permission URL
    scopes = [
        'read_orders',
        'write_orders',
        'read_products',
        'write_products',
        'read_product_listings'
    ]
    
    redirect_uri = f"{os.getenv('APP_URL')}/auth/callback"
    nonce = os.urandom(16).hex()
    
    # Store nonce in session
    session['nonce'] = nonce
    session['shop'] = shop
    
    install_url = f"https://{shop}/admin/oauth/authorize?" + \
                 f"client_id={os.getenv('SHOPIFY_API_KEY')}&" + \
                 f"scope={','.join(scopes)}&" + \
                 f"redirect_uri={redirect_uri}&" + \
                 f"state={nonce}"
    
    return redirect(install_url)

@app.route('/auth/callback')
def callback():
    """OAuth callback handler"""
    try:
        if request.args.get('state') != session.get('nonce'):
            return 'Invalid state parameter', 400

        shop = session.get('shop')
        if not shop:
            return 'Missing shop parameter', 400

        # Exchange temporary code for permanent token
        access_token_url = f"https://{shop}/admin/oauth/access_token"
        
        response = requests.post(access_token_url, json={
            'client_id': os.getenv('SHOPIFY_API_KEY'),
            'client_secret': os.getenv('SHOPIFY_API_SECRET'),
            'code': request.args.get('code')
        })
        
        if response.status_code == 200:
            access_token = response.json()['access_token']
            
            # Create metafield definitions
            create_metafield_definitions(shop, access_token)
            
            return 'App successfully installed with metafield definitions!'
        else:
            return f'Error getting access token: {response.text}', 400
            
    except Exception as e:
        logger.error(f"Installation error: {str(e)}")
        return f'Error during installation: {str(e)}', 400

def get_product_metafields(product_id):
    """Fetch product metafields from Shopify"""
    try:
        shop_url = os.getenv('SHOPIFY_SHOP_URL')
        access_token = os.getenv('SHOPIFY_ACCESS_TOKEN')
        
        headers = {
            'X-Shopify-Access-Token': access_token,
            'Content-Type': 'application/json'
        }
        
        url = f"https://{shop_url}/admin/api/2024-01/products/{product_id}/metafields.json"
        
        logger.info(f"Fetching metafields for product {product_id}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        metafields = response.json().get('metafields', [])
        logger.info(f"Received metafields: {json.dumps(metafields, indent=2)}")
        
        # Initialize files structure
        files = {
            'preview_files': {},
            'print_files': {}
        }
        
        # Map metafields to file structure
        metafield_mapping = {
            'print_files': 'front',
            'front_preview_file': ('preview_files', 'front'),
            'back_preview_file': ('preview_files', 'back'),
            'back_print_files': ('print_files', 'back'),
            'neck_print_files': ('print_files', 'neck'),
            'neck_preview_file': ('preview_files', 'neck')
        }
        
        for metafield in metafields:
            if metafield.get('namespace') == 'custom':
                key = metafield.get('key')
                value = metafield.get('value')
                
                if key in metafield_mapping:
                    if isinstance(metafield_mapping[key], tuple):
                        file_type, location = metafield_mapping[key]
                        files[file_type][location] = value
                    else:
                        # Handle front print files
                        files['print_files']['front'] = value
        
        logger.info(f"Processed files structure: {json.dumps(files, indent=2)}")
        return files
        
    except Exception as e:
        logger.error(f"Error fetching product metafields: {str(e)}")
        return {'preview_files': {'front': ''}, 'print_files': {'front': ''}}

@app.route('/webhook/orders', methods=['POST'])
def order_webhook():
    """Handle incoming order webhooks"""
    try:
        logger.info("=== New Order Webhook Received ===")
        
        shopify_order = request.json
        logger.info(f"Processing Shopify order number: {shopify_order.get('order_number')}")
        
        # Get shipping address details
        shipping_address = shopify_order.get('shipping_address', {})
        
        # Ensure required fields are present
        address_to = {
            "address1": shipping_address.get('address1', ''),
            "address2": shipping_address.get('address2') or '',
            "city": shipping_address.get('city', ''),
            "zip": shipping_address.get('zip') or shipping_address.get('postal_code', '46168'),
            "country": shipping_address.get('country_code', 'US'),
            "region": shipping_address.get('province_code', 'IN'),
            "first_name": shipping_address.get('first_name', ''),
            "last_name": shipping_address.get('last_name', ''),
            "phone": shipping_address.get('phone') or ''
        }

        if shopify_order.get('email'):
            address_to['email'] = shopify_order.get('email')

        dimona_order = {
            "id": str(shopify_order.get('order_number', '')),
            "sample": False,
            "reprint": False,
            "xqc": False,
            "address_to": address_to,
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
            "items": []
        }

        # Process line items
        for item in shopify_order.get('line_items', []):
            logger.info(f"Processing line item: {json.dumps(item, indent=2)}")
            
            # Get product metafields
            product_id = item.get('product_id')
            if product_id:
                files = get_product_metafields(product_id)
                preview_files = files['preview_files']
                print_files = files['print_files']
            else:
                preview_files = {'front': ''}
                print_files = {'front': ''}
            
            # Only include locations that have files
            preview_files = {k: v for k, v in preview_files.items() if v}
            print_files = {k: v for k, v in print_files.items() if v}
            
            # Ensure at least front exists
            if not preview_files:
                preview_files['front'] = ''
            if not print_files:
                print_files['front'] = ''

            transformed_item = {
                "id": str(item.get('id')),
                "sku": item.get('sku', ''),
                "preview_files": preview_files,
                "print_files": print_files,
                "quantity": item.get('quantity', 1)
            }
            
            logger.info(f"Transformed item: {json.dumps(transformed_item, indent=2)}")
            dimona_order['items'].append(transformed_item)

        # Log the final payload
        logger.info("=== Sending to Dimona API ===")
        logger.info(f"Order payload:\n{json.dumps(dimona_order, indent=2)}")
        
        headers = {
            'Authorization': f'Bearer {os.getenv("DIMONA_API_TOKEN")}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        response = requests.post(
            "https://dimonatee.com/api/v2021/orders",
            json=dimona_order,
            headers=headers
        )
        
        logger.info(f"Dimona API Response Status: {response.status_code}")
        logger.info(f"Dimona API Response Body: {response.text}")
        
        if response.status_code != 200:
            raise Exception(f"Dimona API error: {response.text}")
        
        return jsonify({
            'status': 'success',
            'dimona_response': response.json()
        })
        
    except Exception as e:
        logger.error("=== Error Processing Order ===")
        logger.error(f"Error: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 400

if __name__ == '__main__':
    logger.info("=== Starting Server ===")
    app.run(port=52097, debug=True)