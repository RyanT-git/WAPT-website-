from flask import Flask, request, render_template, jsonify
import requests
from bs4 import BeautifulSoup, Comment

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def handle_scan():
    url = request.form.get('url')
    scan_type = request.form.get('scanType')

    # Ensure URL is provided and starts with http:// or https://
    if url:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
    else:
        return jsonify({'error': 'No URL provided. Please enter a valid URL.'})

    if scan_type == 'quick':
        scan_result = perform_quick_scan(url)
    else:
        scan_result = {"message": "Other scan types not yet implemented."}

    return jsonify(scan_result)

def perform_quick_scan(url):
    headers = {'User-Agent': 'Mozilla/5.0'}  # Sending a typical browser user-agent
    try:
        response = requests.get(url, timeout=10, headers=headers, verify=False)  # Added headers and disabled SSL verification
        if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')
            vulnerabilities = check_for_vulnerabilities(soup, url)
            return {'url': url, 'vulnerabilities': vulnerabilities}
        else:
            return {'error': f"Failed to retrieve URL. Status code: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def check_for_vulnerabilities(soup, url):
    vulnerabilities = []

    # Check forms for potential issues
    for form in soup.find_all('form'):
        action = form.get('action', '').lower()
        method = form.get('method', '').lower()

        # Check if action is potentially insecure
        if action in ['', url, '#'] or not action.startswith(('http://', 'https://')):
            vulnerabilities.append({'type': 'Form Action', 'details': 'Form with potentially unsafe action attribute found.'})
        
        # Check for insecure form submission methods
        if method == 'get':
            vulnerabilities.append({'type': 'Form Method', 'details': 'Form using GET method for sensitive data transmission.'})

    # Check input fields for potential issues
    for input in soup.find_all('input'):
        name = input.get('name', '').lower()
        input_type = input.get('type', '').lower()
        autocomplete = input.get('autocomplete', '').lower()

        # Check for sensitive input fields that are not properly secured
        if 'password' in name and input_type != 'password':
            vulnerabilities.append({'type': 'Input Type', 'details': f'Password input "{name}" is not of type password.'})

        # Check for autocomplete on sensitive fields
        if 'off' not in autocomplete and any(sub in name for sub in ['password', 'user']):
            vulnerabilities.append({'type': 'Input Autocomplete', 'details': f'Input "{name}" may leak sensitive data through autocomplete.'})

    # Check for hidden inputs
    for hidden_input in soup.find_all('input', type='hidden'):
        vulnerabilities.append({'type': 'Hidden Input', 'details': f'Hidden input found: {hidden_input.get("name", "No name")}'})

    # Check for external links and JavaScript protocol handlers
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('http://') or href.startswith('https://'):
            if not href.startswith(url):
                vulnerabilities.append({'type': 'External Link', 'details': f'External link found: {href}'})
        elif href.startswith('javascript:'):
            vulnerabilities.append({'type': 'JavaScript Link', 'details': f'JavaScript link found: {href}'})

    # Check for verbose error messages (simple example, might need more complex heuristics)
    for error in soup.find_all(text=lambda text: "error" in text.lower()):
        vulnerabilities.append({'type': 'Verbose Error Message', 'details': f'Potential verbose error message found: {error.strip()}'})

    # Check for inline scripts and external scripts from untrusted sources
    for script in soup.find_all('script'):
        src = script.get('src', '')
        if not src:  # Inline script
            vulnerabilities.append({'type': 'Inline Script', 'details': 'Inline script found, potential for XSS.'})
        elif not src.startswith(('http://', 'https://')):
            vulnerabilities.append({'type': 'External Script', 'details': f'Script from unknown source: {src}'})

    # Add more checks as necessary...
    
    return vulnerabilities




if __name__ == '__main__':
    app.run(debug=True)

