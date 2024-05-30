import re
import os
import json
import httpx
import shlex
import base64
import argparse
import requests
import importlib.util
from textwrap import dedent
from enum import Enum, auto
from datetime import datetime
from typing import Optional, Tuple, Dict, List

rich_installed = importlib.util.find_spec('rich') is not None

if rich_installed:
    from rich.console import Console
    from rich.table import Table
    from rich import print
    console = Console()
else:
    console = None

#  todo - check entire request and response for JWTs
#  todo - check for JWT in headers and body

class RequestType(Enum):
    CURL = auto()
    HTTP = auto()

class Token:
    def __init__(self, header: str, payload: str, signature: str):
        self.header = header
        self.payload = payload
        self.signature = signature
        self.algorithm = self.decode(header).get('alg')
        # Decoded versions
        self.decoded_header = self.decode(header)
        self.decoded_payload = self.decode(payload)

    @staticmethod
    def set_url(self, url: str):
        self.url = url

    @staticmethod
    def decode(data: str):
        # Assuming the data is base64 encoded JSON
        decoded_bytes = base64.urlsafe_b64decode(data + '==')  # Padding correction
        decoded_str = decoded_bytes.decode('utf-8')
        return json.loads(decoded_str)

def parse_jwt(jwt: str) -> Token:
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format. JWT should have 3 parts separated by '.'")
    return Token(parts[0], parts[1], parts[2])

def get_jwt_encryption_type(jwt: str) -> Optional[str]:
    """
    Extracts the encryption type (algorithm) from a JWT token.

    Args:
        jwt (str): The JWT token as a string.

    Returns:
        Optional[str]: The encryption type (algorithm) if found, None otherwise.
    """
    try:
        # Split the JWT token into its components
        parts = jwt.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format. A JWT should have 3 parts separated by '.'")

        # Decode the header part from Base64 URL format
        header = parts[0]
        header_decoded_bytes = base64.urlsafe_b64decode(header + '==')  # Pad with == to ensure correct padding
        header_decoded_str = header_decoded_bytes.decode('utf-8')
        header_data = json.loads(header_decoded_str)

        # Return the algorithm used for encryption, indicated by 'alg' key
        return header_data.get('alg')
    except Exception as e:
        print(f"Error decoding JWT encryption type: {e}")
        return None

def determine_request_type(request: str) -> RequestType:
    if request.startswith("curl "):
        return RequestType.CURL
    elif request.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
        return RequestType.HTTP
    else:
        raise ValueError("Unknown request type")

def execute_request(request: str, http: bool) -> requests.Response:
    """
    Executes a given request based on its type (curl command or HTTP request).

    Args:
        request (str): The request to be executed.
        http (bool): Flag indicating whether to use HTTP instead of HTTPS.

    Returns:
        requests.Response: The response from the server.
    """
    request_type = determine_request_type(request)
    if request_type == RequestType.CURL:
        return execute_curl_command(request, http)
    elif request_type == RequestType.HTTP:
        return execute_http_request(request, http)
    else:
        raise ValueError("Unsupported request type")

def invalidate_jwt(jwt):
    header, payload, signature = jwt.split('.')
    # Decode and alter the payload
    decoded_payload = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded_payload["exp"] = 0  # Invalidate token by setting an expired timestamp
    # Re-encode the payload
    new_payload = base64.urlsafe_b64encode(json.dumps(decoded_payload).encode()).rstrip(b'=').decode()
    # Return the JWT without a valid signature
    return f'{header}.{new_payload}.invalid-signature'

def remove_signature_from_jwt(jwt):
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format. JWT should have 3 parts separated by '.'")
    # Rejoin the header and payload without the signature
    unsigned_jwt = '.'.join(parts[:2]) + '.'
    return unsigned_jwt

def replace_jwt_in_request(request: str, jwt: str) -> str:  

    if is_curl_command(request):
        request = request.replace("$'", "'")
        request = request.replace('\\"', '"')
        modified_request, count = re.subn(r"-H\s*[\"']?Authorization:\s*Bearer\s*([^'\"\s]+)[\"']?", f'-H "Authorization: Bearer {jwt}"', request, re.IGNORECASE)
        if count == 0:
            print("No JWT found or replaced in the curl command.")
    else:
        modified_request = re.sub(r"Authorization:\s*Bearer\s*(.*)", f"Authorization: Bearer {jwt}", request, flags=re.IGNORECASE)        
    return modified_request

def is_curl_command(line: str) -> bool:
    return line.startswith("curl ")

def is_http_request(line: str) -> bool:
    return line.startswith("GET ") or line.startswith("POST ") or line.startswith("PUT ") or line.startswith("DELETE ")

def execute_curl_command(command: str, http: bool) -> Tuple[Optional[requests.Response], Dict[str, str]]:
    try:
        # Preprocess command to handle shell-like syntax correctly
        command = command.replace("$'", "'")
        command = command.replace('\\"', '"')

        # Use shlex.split to correctly handle spaces within quotes
        parts = shlex.split(command)
        
        # Initialize default values
        method = "GET"  # Default method
        url = ""
        headers = {}
        payload = None
        if http:
            scheme = 'http'
        else:
            scheme = 'https'  # Default to HTTPS

        # Process each part of the command
        for i, part in enumerate(parts):
            if part in ['-X', '--request']:
                method = parts[i + 1]
            elif part in ['-H', '--header']:
                header = parts[i + 1]
                key, value = header.split(':', 1)
                if key.strip().lower() == 'scheme':  # Custom scheme header
                    scheme = value.strip().lower()
                    if scheme not in ['http', 'https']:
                        raise ValueError("Invalid scheme specified. Must be 'http' or 'https'.")
                else:
                    headers[key.strip()] = value.strip()
            elif part == '--data-binary' or part in ['-d', '--data']:
                payload = parts[i + 1]
            elif part.startswith('http://') or part.startswith('https://'):
                url = part
            elif i == 0:  # The first non-option argument should be the URL if not explicitly given
                url = f"{scheme}://{part}"

        if not url:
            raise ValueError("URL not found in the curl command.")

        # print(f"URL: {url}")
        # print(f"Method: {method}")
        # print("Headers:")
        # for key, value in headers.items():
        #     print(f"    {key}: {value}")
        # print(headers)
        # if payload:
        #     print(f"Payload: {payload}")

        # Perform the request
        response = requests.request(method, url, headers=headers, data=payload)

        return response, headers

    except requests.exceptions.ConnectionError as e:
        print(f"[red]Error: Unable to connect to the URL {url}. Please check your network connection and ensure the URL is correct.[/red]")
        return None, None

    except requests.exceptions.RequestException as e:
        print(f"[bold red]Error:[/bold red] An error occurred while making the request to {url}. {str(e)}")
        print(f"[red]Error: An error occurred while making the request to {url}. {str(e)}[/red]")
        return None, None

def get_jwt_from_request(request: str) -> Optional[str]:
    """
    Extracts the JWT (JSON Web Token) from the given HTTP request. This function supports both curl commands and HTTP requests.
    NOTE!!!!: Currently, only Bearer tokens are supported.

    Args:
        request (str): The HTTP request containing the JWT.

    Returns:
        Optional[str]: The JWT if found, None otherwise.
    """
    if is_curl_command(request):
        request = request.replace("$'", "'")
        request = request.replace('\\"', '"')
        jwt_match = re.search(r"-H\s*[\"']?Authorization:\s*Bearer\s*([^'\"\s]+)[\"']?", request, re.IGNORECASE)
    else:
        jwt_match = re.search(r"Authorization:\s*Bearer\s*(.*)", request, re.IGNORECASE)

    if jwt_match:
        return jwt_match.group(1)
    return None

def remove_jwt_from_request(request: str) -> str:
    jwt_match = get_jwt_from_request(request)
    
    if jwt_match:
        modified_request = request.replace(jwt_match, "")
        return modified_request
    return request

def execute_http_request(request: str, http: bool) -> Tuple[Optional[httpx.Response], Dict[str, str]]:
    """
    Executes an HTTP request based on the provided request string.

    Args:
        request (str): The HTTP request string.
        http (bool): A flag indicating whether to use HTTP or HTTPS.

    Returns:
        Tuple[Optional[httpx.Response], Dict[str, str]]: A tuple containing the response object and the headers.

    Raises:
        ValueError: If an invalid scheme is specified in the 'Scheme' header.

    """
    print("inside execute http request")
    try:
        lines = request.split('\n')
        method, path, _ = lines[0].split()
        headers = {}
        payload = None
        if http:
            scheme = 'http'
        else:
            scheme = 'https'  # Default to HTTPS
        
        # Find the blank line that separates headers from payload
        blank_line_index = next((i for i, line in enumerate(lines) if line.strip() == ''), len(lines))
        
        # Extract headers and check for the Scheme header
        for line in lines[1:blank_line_index]:
            if ':' in line:
                key, value = line.split(':', 1)
                if key.strip().lower() == 'scheme':  # Custom scheme header
                    scheme = value.strip().lower()
                    if scheme not in ['http', 'https']:
                        raise ValueError("Invalid scheme specified. Must be 'http' or 'https'.")
                else:
                    headers[key.strip()] = value.strip()

        # Ensure the 'Scheme' header doesn't get passed to the request
        headers.pop('Scheme', None)
        
        # Extract payload if present
        if blank_line_index + 1 < len(lines):
            payload = '\n'.join(lines[blank_line_index + 1:])
        
        url = f"{scheme}://{headers['Host']}{path}"
        response = httpx.request(method, url, headers=headers, data=payload)
        return response, headers
    except httpx.HTTPStatusError as e:
        print(f"[bold red]Error:[/bold red] An error occurred while making the request to {url}. {str(e)}")
        return None, None
    except httpx.RequestError as e:
        print(f"[red]Error: Unable to connect to the URL {url}. Please check your network connection and ensure the URL is correct.[/red]")
        return None, None

def is_jwt_required(request: str, original_response: httpx.Response, verbose: bool, http: bool) -> bool:
    """
    Checks if a JWT (JSON Web Token) is required for the given request.

    Args:
        request (str): The original HTTP request.
        original_response (httpx.Response): The original response received from the server.

    Returns:
        bool: True if the JWT is required, False otherwise.
    """

    modified_request = remove_jwt_from_request(request)
    modified_response, _ = execute_request(modified_request, http)

    if modified_response is not None:
        print_request_response(modified_request, modified_response, verbose)

        if original_response.status_code != modified_response.status_code:
            print(f"Response codes do not match: {original_response.status_code} != {modified_response.status_code}")
            return True

        if 'Content-Length' in modified_response.headers and 'Content-Length' in original_response.headers:
            if modified_response.headers['Content-Length'] != original_response.headers['Content-Length']:
                print(f"Content lengths do not match: {modified_response.headers['Content-Length']} != {original_response.headers['Content-Length']}")
                return True

        if original_response.text != modified_response.text:
            print("Response bodies do not match:")
            print("Modified response body:")
            print(modified_response.text)
            print("Original response body:")
            print(original_response.text)
            return True

        return False 

    return True # Default to True if the modified request fails

def execute_request(request: str, http: bool) -> Tuple[Optional[httpx.Response], Dict[str, str]]:
    """
    Executes an HTTP request based on the provided request string.

    Args:
        request (str): The HTTP request string.
        http (bool): A flag indicating whether to use HTTP or HTTPS.

    Returns:
        Tuple[Optional[httpx.Response], Dict[str, str]]: A tuple containing the response object and the headers.

    Raises:
        ValueError: If an invalid scheme is specified in the 'Scheme' header.
    """
    try:
        lines = request.split('\n')
        method, path, _ = lines[0].split()
        headers = {}
        payload = None
        scheme = 'http' if http else 'https'
        
        blank_line_index = next((i for i, line in enumerate(lines) if line.strip() == ''), len(lines))
        
        for line in lines[1:blank_line_index]:
            if ':' in line:
                key, value = line.split(':', 1)
                if key.strip().lower() == 'scheme':
                    scheme = value.strip().lower()
                    if scheme not in ['http', 'https']:
                        raise ValueError("Invalid scheme specified. Must be 'http' or 'https'.")
                else:
                    headers[key.strip()] = value.strip()

        headers.pop('Scheme', None)
        
        if blank_line_index + 1 < len(lines):
            payload = '\n'.join(lines[blank_line_index + 1:])
        
        url = f"{scheme}://{headers['Host']}{path}"
        response = httpx.request(method, url, headers=headers, data=payload)
        return response, headers
    except httpx.RequestError as e:
        print(f"[red]Error: Unable to connect to the URL {url}. Please check your network connection and ensure the URL is correct.[/red]")
        return None, None
    except httpx.HTTPStatusError as e:
        print(f"[bold red]Error:[/bold red] An error occurred while making the request to {url}. {str(e)}")
        return None, None

def is_jwt_signature_checked(request: str, original_response: httpx.Response, verbose, http: bool) -> bool:
    """
    Checks if the signature of a JWT (JSON Web Token) is verified by the server.

    Args:
        request (str): The original HTTP request.
        original_response (httpx.Response): The original response received from the server.

    Returns:
        bool: True if the JWT signature is checked, False otherwise.
    """

    jwt = get_jwt_from_request(request)

    if jwt is not None:
        invalid_jwt = remove_signature_from_jwt(jwt)
        modified_request = replace_jwt_in_request(request, invalid_jwt)
        modified_response, _ = execute_request(modified_request, http)
    else:
        modified_response = None

    if modified_response is not None:
        print_request_response(modified_request, modified_response, verbose)

        if original_response.status_code != modified_response.status_code:
            print(f"Response codes do not match: {original_response.status_code} != {modified_response.status_code}")
            return True

        if 'Content-Length' in modified_response.headers and 'Content-Length' in original_response.headers:
            if modified_response.headers['Content-Length'] != original_response.headers['Content-Length']:
                print(f"Content lengths do not match: {modified_response.headers['Content-Length']} != {original_response.headers['Content-Length']}")
                return True

        if original_response.text != modified_response.text:
            print("Response bodies do not match:")
            print("Modified response body:")
            print(modified_response.text)
            print("Original response body:")
            print(original_response.text)
            return True

        return False 

    return True # Default to True if the modified request fails

def print_request_response(request: str, response: httpx.Response, verbose: bool) -> List[Tuple[str, str]]:
    rows = []
    if verbose:
        response_headers = response.headers
        response_text = response.text
        response_status_code = response.status_code
        formatted_headers = "\n".join([f"{key}: {value}" for key, value in response_headers.items()])
        row = (request, f"HTTP/2 {response_status_code} OK\n{formatted_headers}\n\n{response_text}")
        rows.append(row)
    return rows

def print_invalid_input_message() -> None:
    console = Console()
    message = dedent("""
        [yellow]Invalid input format. Please provide a valid curl command or HTTP request.[/yellow]
        
        [dim]Example of a valid curl command:[/dim]
            curl -X GET https://api.example.com/resource -H 'Authorization: Bearer <JWT>'
        
        [dim]Example of a valid HTTP request:[/dim]
            GET /resource HTTP/1.1
            Host: api.example.com
            Authorization: Bearer <JWT>
    """)
    console.print(message)
    
def print_jwt(request: str) -> List[Tuple[str, str]]:
    """
    Prepares JWT (JSON Web Token) row for the table based on the given request.

    Args:
        request (str): The HTTP request or curl command.

    Returns:
        List[Tuple[str, str]]: A list containing a tuple for the table row.
    """
    rows = []  # Initialize an empty list for rows

    # Extract JWT from the request
    jwt = get_jwt_from_request(request)
    if jwt:
        # Add a row for the JWT found
        rows.append(("JWT Found", f"[yellow]{jwt}[/yellow]"))
    else:
        # If no JWT found, add a row indicating this
        rows.append(("JWT Found", "No JWT found in the request."))
    
    return rows    

# Function to convert Unix timestamp to readable date in UTC
def timestamp_to_utc(ts):
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S (UTC)')

# Function to calculate the difference between two timestamps
def calculate_difference(ts1, ts2):
    diff = datetime.fromtimestamp(ts2) - datetime.fromtimestamp(ts1)
    days, seconds = diff.days, diff.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{days} days, {hours} hours, {minutes} mins"

def read_request_file(file_path: str) -> Optional[str]:
    """
    Read the contents of a file and return them as a string.

    Args:
        file_path (str): The path to the file to be read.

    Returns:
        Optional[str]: The contents of the file as a string, or None if there was an error.

    Raises:
        IOError: If there was an error opening the file.
    """
    try:
        with open(file_path, "r") as file:
            return file.read().strip()
    except IOError as e:
        print(f"Error opening file: {e}")
        return

def process_request(request_content: str, verbose: bool, http: bool) -> None:
    """
    Process the request and perform JWT checks on the response.

    Args:
        request_content (str): The content of the request.
        verbose (bool): Flag indicating whether to print verbose output.
        http (bool): Flag indicating whether the request is an HTTP request.

    Returns:
        None
    """
    # Process the request and get the response
    original_response, _ = None, {}
    curl = is_curl_command(request_content)
    http = is_http_request(request_content)

    if curl:
    # Assuming you have a separate function to handle curl requests
        original_response, _ = execute_request(request_content, curl)
    elif http:
        original_response, _ = execute_request(request_content, http)
    else:
        print(f"Unable to identify file as a valid request. Please check {request_content} to ensure it's a valid request.")
        return

    # Only proceed with JWT checks if the original response was successfully obtained
    if original_response:
        url = original_response.url
        print(f"\n[green][+] URL:[/green] {url}")
        jwt_token = get_jwt_from_request(request_content)
        if jwt_token:
            print("[green][+] JWT:[/green]", jwt_token)
            my_token = parse_jwt(jwt_token)
            print("\n[bold white]Token Header Values...[/bold white]\n")            
            for key, value in my_token.decoded_header.items():
                print(f"[green][+][/green] {key} = \"{value}\"")

            print("\n[bold white]Token Payload Values...[/bold white]\n")
            for key, value in my_token.decoded_payload.items():
                if key == "exp" or key == "iat" or key == "nbf":
                    print(f"[green][+][/green] {key} = {value} ==> TIMESTAMP = {timestamp_to_utc(value)}")
                else:       
                    print(f"[green][+][/green] {key} = \"{value}\"")

            if 'exp' in my_token.decoded_payload:
                print("\n[bold white]Expiration Timestamps...[/bold white]\n")
                current_timestamp = int(datetime.now().timestamp())
                print(f"[green][+][/green] Current timestamp: {current_timestamp} ==> {timestamp_to_utc(current_timestamp)}")
                exp_to_current_difference = calculate_difference(current_timestamp, my_token.decoded_payload['exp'])
                print("[green][+][/green] exp was seen")
                print(f"[green][+][/green] exp is later than current timestamp by: {exp_to_current_difference}")

                # Check if the token is expired
                current_timestamp = int(datetime.now().timestamp())
                if my_token.decoded_payload['exp'] < current_timestamp:
                    print("[bold red][-] TOKEN IS EXPIRED![/bold red]")
                else:
                    print("[bold green][+] TOKEN IS STILL VALID![/bold green]")

            print("\n[bold white]Security Checks...[/bold white]\n")
            # Check and print if JWT is required
            if is_jwt_required(request_content, original_response, verbose, http):
                print(f"[bold green][+] JWT is required for HTTP request to {url}[/bold green]")
            else:
                print(f"[bold red][-] JWT not needed for HTTP request to {url}[/bold red]")

            # Check and print if JWT signature is checked
            if is_jwt_signature_checked(request_content, original_response, verbose, http):
                print(f"[bold green][+] JWT signature is checked for HTTP request to {url}[/bold green]")
            else:
                print("[bold red][-] JWT accepted without signature! Changing JWT payloads should work![/bold red]")   
        
        else:
            print("No JWT Token Found")

def main() -> None:
    parser = argparse.ArgumentParser(description="Execute curl command or HTTP request from a file.")
    parser.add_argument("path", help="Path to the file or directory containing the curl command(s) or HTTP request(s).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to see the request and response.")
    parser.add_argument("--http", action="store_true", help="Check HTTP, Default is HTTPS.")
    args = parser.parse_args()


    if os.path.isdir(args.path):
        # If it's a directory, iterate over each file in the directory
        for filename in os.listdir(args.path):
            file_path = os.path.join(args.path, filename)
            if os.path.isfile(file_path):  # Ensuring it's a file
                print(f"\nProcessing {file_path}...")
                request_content = read_request_file(file_path)
                process_request(request_content, args.verbose, args.http)
    elif os.path.isfile(args.path):
        # If it's a single file, process it directly
        request_content = read_request_file(args.path)
        process_request(request_content, args.verbose, args.http)
    else:
        print(f"The specified file or directory does not exist: {args.path}")



if __name__ == "__main__":
    main()


