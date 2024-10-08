#! /usr/bin/env python3

import re
import os
import json
import pytz
import httpx
import shlex
import base64
import asyncio
import argparse
import importlib.util
from textwrap import dedent
from enum import Enum, auto
from ask_openai import ask_openai
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, List

rich_installed = importlib.util.find_spec('rich') is not None

if rich_installed:
    from rich.console import Console
    from rich.table import Table
    from rich import print
    console = Console()
else:
    console = None

#  I used httpx over requests for HTTP2 support
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

def parse_jwt(jwt: str, verbose: bool = False) -> Optional[Token]:
    parts = jwt.split('.')
    if len(parts) != 3:
        if verbose:
            print("Invalid JWT format. JWT should have 3 parts separated by '.'")
        return None
    return Token(parts[0], parts[1], parts[2])

# Helper function to check if input is a JWT 
def is_jwt(input_string: str) -> bool:
    parts = input_string.split('.')
    return len(parts) == 3  # Simple check if it's a valid-looking JWT (header, payload, signature)


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

def add_jwtmap_cookie(request: str, cookie_value: str) -> str:
    """
    Adds a jwtmap cookie to the headers of an HTTP request.

    Args:
        request (str): The HTTP request string or a curl command.
        cookie_value (str): The cookie_value token to be added to the headers.

    Returns:
        str: The modified request with the new jwtmap cookie added to the headers.
    """
    cookie_name = "jwtmap"  # Define the name of the cookie to be used
    
    if is_curl_command(request):
        # If the request is a curl command, add or update the 'Cookie' header
        if "-H '{cookie_name}:" in request or '-H "{cookie_name}:' in request:
            # If a Cookie header already exists, append the JWT cookie to it
            modified_request = re.sub(
                r"(-H\s*['\"]{cookie_name}:\s*)([^'\"\s]+)(['\"])", 
                lambda match: f"{match.group(1)}{match.group(2)}; {cookie_value}{match.group(3)}", 
                request, 
                flags=re.IGNORECASE)
        else:
            # If no Cookie header exists, add one
            modified_request = request.rstrip() + f' -H "{cookie_name}: {cookie_value}"'
    else:
        # If the request is an HTTP request format, add or update the 'Cookie' header
        if "{cookie_name}:" in request:
            # If a Cookie header already exists, append the JWT cookie to it
            modified_request = re.sub(
                rf"({cookie_name}:\s*)([^'\s]+)",  # Corrected the regex pattern
                lambda match: f"{match.group(1)}{match.group(2)}; {cookie_value}", 
                request, 
                flags=re.IGNORECASE)
        else:
            # Insert a Cookie header into the request
            headers_end = request.index("\n")  # Find end of the start line (e.g., GET / HTTP/1.1)
            modified_request = request[:headers_end + 1] + f"{cookie_name}: {cookie_value}\n" + request[headers_end + 1:]

    return modified_request

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

def is_burp_xml(line: str) -> bool:
    return line.startswith("<?xml version=")

def execute_curl_command(command: str, use_http: bool, proxy: Optional[Dict[str, str]] = None) -> Tuple[Optional[httpx.Response], Dict[str, str]]:
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
        scheme = 'http' if use_http else 'https'  # Determine the protocol based on the use_http flag

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

        proxies = {"http": proxy, "https": proxy} if proxy else None

        # Perform the request
        response = httpx.request(method, url, headers=headers, data=payload, proxies=proxies)

        return response, headers

    except httpx.RequestError as e:
        print(f"[red]Error: Unable to connect to the URL {url}. Please check your network connection and ensure the URL is correct.[/red]")
        return None, None

    except Exception as e:
        print(f"[bold red]Error:[/bold red] An error occurred while making the request to {url}. {str(e)}")
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
    elif is_http_request(request):
        jwt_match = re.search(r"Authorization:\s*Bearer\s*(.*)", request, re.IGNORECASE)
    else:
        jwt_match = re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', request, re.IGNORECASE)

    if jwt_match:
        return jwt_match.group(1)
    return None

def remove_jwt_from_request(request: str) -> str:
    jwt_match = get_jwt_from_request(request)
    
    if jwt_match:
        modified_request = request.replace(jwt_match, "")
        return modified_request
    return request

def execute_http_request(request: str, use_http: bool, proxy: Optional[str] = None) -> Tuple[Optional[httpx.Response], Dict[str, str]]:
    """
    Executes an HTTP request based on the provided request string.

    Args:
        request (str): The HTTP request string.
        use_http (bool): A flag indicating whether to use HTTP or HTTPS. Defaults to HTTPS.
        proxy (Optional[str]): A string representing the proxy URL.

    Returns:
        Tuple[Optional[httpx.Response], Dict[str, str]]: A tuple containing the response object and the headers.

    Raises:
        ValueError: If an invalid protocol is specified in the 'Protocol' header.
    """
    try:
        lines = request.split('\n')
        method, path, http_version = lines[0].split()
        headers = {}
        payload = None
        protocol = 'http' if use_http else 'https'  # Determine the protocol based on the use_http flag
        
        # Find the blank line that separates headers from payload
        blank_line_index = next((i for i, line in enumerate(lines) if line.strip() == ''), len(lines))
        
        # Extract headers and check for the Protocol header
        for line in lines[1:blank_line_index]:
            if ':' in line:
                key, value = line.split(':', 1)
                if key.strip().lower() == 'protocol':  # Custom protocol header
                    protocol = value.strip().lower()
                    if protocol not in ['http', 'https']:
                        raise ValueError("Invalid protocol specified. Must be 'http' or 'https'.")
                else:
                    headers[key.strip().lower()] = value.strip()

        # Ensure the 'Protocol' header doesn't get passed to the request
        # headers.pop('Protocol', None)
        
        # Extract payload if present
        if blank_line_index + 1 < len(lines):
            payload = '\n'.join(lines[blank_line_index + 1:])
        
        # Set the Content-Length header
        if payload is not None:
            headers['content-length'] = str(len(payload))
        else:
            headers['content-length'] = '0'

        url = f"{protocol}://{headers['host']}{path}"

        response = httpx.request(method, url, headers=headers, data=payload, follow_redirects=True, proxy=proxy, verify=False)
   
        return response, headers
    
    except httpx.RequestError as e:
        print(f"[red]Error: Unable to connect to the URL {url}. Please check your network connection and ensure the URL is correct.[/red]")
        return None, None

def execute_request(request: str, use_http: bool, proxy: Optional[Dict[str, str]] = None) -> httpx.Response:
    """
    Executes a given request based on its type (curl command or HTTP request).

    Args:
        request (str): The request to be executed.
        use_http (bool): Flag indicating whether to use HTTP instead of HTTPS.
        proxy (Optional[Dict[str, str]]): A dictionary of proxies to use for the request.

    Returns:
        httpx.Response: The response from the server.
    """
    request_type = determine_request_type(request)
    if request_type == RequestType.CURL:
        return execute_curl_command(request, use_http, proxy)
    elif request_type == RequestType.HTTP:
        return execute_http_request(request, use_http, proxy)
    else:
        raise ValueError("Unsupported request type")

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

def timestamp_to_utc(ts):
    # Function to convert Unix timestamp to readable date in UTC
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S (UTC)')

def timestamp_to_local(timestamp, timezone_str='America/Los_Angeles'):
    local_tz = pytz.timezone(timezone_str)
    local_time = datetime.fromtimestamp(timestamp, local_tz)
    return local_time.strftime('%B %d, %Y, at %I:%M:%S %p')

def calculate_difference(current_timestamp, exp_timestamp):
    difference = exp_timestamp - current_timestamp
    return f"{difference} seconds"

def format_time_difference(iat, exp):
    difference = exp - iat
    time_diff = timedelta(seconds=difference)
    hours, remainder = divmod(time_diff.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)

    if seconds > 0:
        minutes += 1

    if minutes == 60:
        hours += 1
        minutes = 0

    if hours > 0:
        return f"{int(hours)} hours {int(minutes)} mins"
    return f"{int(minutes)} mins"

def format_expired_time(expiration, current_timestamp):
    # Calculate the time difference
    delta = current_timestamp - expiration
    
    # Use timedelta to convert the time difference into days, hours, and minutes
    expired_duration = timedelta(seconds=delta)
    
    days = expired_duration.days
    hours, remainder = divmod(expired_duration.seconds, 3600)
    minutes = remainder // 60
    
    return f"{days} days, {hours} hours, and {minutes} minutes"


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

def process_burp_xml(lines: str) -> None:
    
    output_directory = "burp_requests"
    # Create output directory if it doesn't exist
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Regular expression to find base64 encoded data
    base64_pattern = re.compile(r'<request(?: method="GET")? base64="true"><!\[CDATA\[(.*?)\]\]></request>')

    lines = lines.split('\n')
    #print(f"lines: {lines}")
    for line_number, line in enumerate(lines):
        match = base64_pattern.search(line)
        if match:
            base64_data = match.group(1)
            decoded_data = base64.b64decode(base64_data).decode('utf-8')

            # Create a file name based on line number
            output_filename = os.path.join(output_directory, f'request_{line_number}.txt')

            # Write the decoded data to the file
            print(f"Writing decoded data to {output_filename}")
            with open(output_filename, 'w') as output_file:
                output_file.write(decoded_data)

def process_request(request_content: str, ai: bool, verbose: bool, use_http: bool, proxy: Optional[Dict[str, str]] = None) -> None:
    """
    Process the request and perform JWT checks on the response.

    Args:
        request_content (str): The content of the request.
        verbose (bool): Flag indicating whether to print verbose output.
        http (bool): Flag indicating whether the request is an HTTP request.
        proxy (Optional[Dict[str, str]]): A dictionary of proxy to use for the request.

    Returns:
        None
    """
    # Process the request and get the response
    original_response, _ = None, {}
    curl = is_curl_command(request_content)
    http = is_http_request(request_content)
    burp = is_burp_xml(request_content)

    if curl:
    # Assuming you have a separate function to handle curl requests
        original_response, _ = execute_request(request_content, use_http, proxy)
    elif http:
        original_response, _ = execute_request(request_content, use_http, proxy)
    elif burp:
        process_burp_xml(request_content)
    else:
        print(f"Unable to identify file as a valid request. Please check {request_content} to ensure it's a valid request.")
        return

    # Only proceed with JWT checks if the original response was successfully obtained
    if original_response:
        url = original_response.url
        print(f"\n[green][+] URL:[/green] {url}")
        jwt_token = get_jwt_from_request(request_content)
        if jwt_token:
            if ai:
                # Perform AI analysis of the JWT token
                asyncio.run(process_and_analyze_jwt(jwt_token, verbose))
            else:
                process_jwt(jwt_token, verbose)        
                
            print("\n[bold white]Security Checks...[/bold white]\n")

            
            crack_jwt_encryption(jwt_token)

            # Check and print if JWT is required
            if is_jwt_required(request_content, original_response, verbose, use_http, proxy):
                print(f"[bold green][+] JWT is required for HTTP request to [/bold green]{url}")
            else:
                print(f"[bold red][!] JWT not needed for HTTP request to [/bold red]{url}")

            # Check and print if JWT signature is checked
            if is_jwt_signature_checked(request_content, original_response, verbose, use_http, proxy):
                print(f"[bold green][+] JWT signature is checked for HTTP request to [/bold green]{url}")
            else:
                print("[bold red][!] JWT accepted without signature! Changing JWT payloads should work![/bold red]")   
        else:
            print("No JWT Token Found")

def process_jwt(jwt_token: str, verbose: bool) -> None:
    """
    Process the JWT token and print the details.

    Args:
        jwt (str): The JWT token to be processed.

    Returns:
        None
    """
    if verbose:
        print("[green][+] JWT:[/green]", jwt_token)
    my_token = parse_jwt(jwt_token, verbose)
    print("\n[bold white]Token Header Values...[/bold white]\n")            
    for key, value in my_token.decoded_header.items():
        print(f"[green][+][/green] {key} = \"{value}\"")

    print("\n[bold white]Token Payload Values...[/bold white]\n")
    for key, value in my_token.decoded_payload.items():
        if key == "exp" or key == "iat" or key == "nbf":
            print(f"[green][+][/green] {key} = {value} ==> TIMESTAMP = {timestamp_to_local(value)}")
        else:       
            print(f"[green][+][/green] {key} = \"{value}\"")

    if 'exp' in my_token.decoded_payload:
        print("\n[bold white]Expiration Timestamps...[/bold white]\n")
        current_timestamp = int(datetime.now().timestamp())
        issued_at = my_token.decoded_payload.get('iat', 0)
        expiration = my_token.decoded_payload['exp']
        print(f"[green][+][/green] Issued JWT timestamp: {issued_at} ==> {timestamp_to_local(issued_at)}")
        print(f"[green][+][/green] Expiration date of JWT: {expiration} ==> {timestamp_to_local(expiration)}")
        print(f"[green][+][/green] Current date and time: {current_timestamp} ==> {timestamp_to_local(current_timestamp)}")
        
        token_validity = format_time_difference(issued_at, expiration)
        print(f"[green][+][/green] JWT Token valid for {token_validity} ({format_expired_time(issued_at, expiration)})")

        five_hours = timedelta(hours=5)
        issued_at_datetime = datetime.fromtimestamp(issued_at)
        expiration_datetime = datetime.fromtimestamp(expiration)
        if expiration_datetime - issued_at_datetime > five_hours:
            print(f"[bold red][!] JWT Token valid for more than 5 hours[/bold red]")  

        
        # Check if the token is expired
        if expiration < current_timestamp:
            expired_duration = format_expired_time(expiration, current_timestamp)
            print(f"[bold red][!] TOKEN IS EXPIRED![/bold red] Token has been expired for {expired_duration}")
        else:
            print("[bold green][+] TOKEN IS STILL VALID![/bold green]")
    else:
        print("[bold red][!] JWT does not contain an expiration timestamp![/bold red]")

async def ask_openai_jwt_analysis(jwt_header: Dict[str, any], jwt_payload: Dict[str, any]) -> str:
    """
    Ask OpenAI to analyze the given JWT header and payload.

    Args:
        jwt_header (Dict[str, Any]): The decoded JWT header.
        jwt_payload (Dict[str, Any]): The decoded JWT payload.

    Returns:
        str: The OpenAI analysis result.
    """
    # Format the header and payload for OpenAI analysis
    header_details = "\n".join([f"{key}: {value}" for key, value in jwt_header.items()])
    payload_details = "\n".join([f"{key}: {value}" if key not in ["exp", "iat", "nbf"] else f"{key}: {value} (timestamp: {timestamp_to_local(value)})" for key, value in jwt_payload.items()])

    # Create a detailed question for OpenAI
    question = (
        "Please analyze the following JWT token. Here is the decoded header:\n\n"
        f"{header_details}\n\n"
        "And here is the decoded payload:\n\n"
        f"{payload_details}\n\n"
        "Provide insights into the structure and fields, explain any significant security issues, and evaluate the claims."
    )

    # Provide additional context to OpenAI
    context = (
        "Analyze the token and consider things like whether timestamps are valid, if required fields are present, "
        "and if there are any potential security concerns. Provide a summary of the JWT's purpose based on the data."
    )

    # Send the question and context to OpenAI
    answer = await ask_openai(question, context)
    
    return answer

async def process_and_analyze_jwt(jwt_token: str, verbose: bool) -> None:
    """
    Process the JWT token, print the details, and analyze it using OpenAI.
    
    Args:
        jwt_token (str): The JWT token to be processed and analyzed.
        verbose (bool): Flag to print additional information.

    Returns:
        None
    """
    # Process the JWT locally
    process_jwt(jwt_token, verbose)
    
    # Parse the token to get header and payload for OpenAI
    my_token = parse_jwt(jwt_token, verbose)
    
    # Ask OpenAI to analyze the token (JWT Header and Payload)
    ai_analysis = await ask_openai_jwt_analysis(my_token.decoded_header, my_token.decoded_payload)
    
    # Print the OpenAI analysis
    print("\n[bold green]OpenAI Analysis of JWT:[/bold green]\n", ai_analysis)


def is_crackable_encryption(jwt: str) -> str:
    """
    Checks if the encryption type of a JWT (JSON Web Token) is crackable.

    Args:
        jwt (str): The JWT token as a string.

    Returns:
        str: The encryption type if it is crackable, an empty string otherwise.
    """
    encryption_type = get_jwt_encryption_type(jwt)
    if encryption_type:
        # Dictionary mapping encryption types to their corresponding values
        crackable_encryptions = {
            'hs256': 'HMAC-SHA256',
            'hs384': 'HMAC-SHA384',
            'hs512': 'HMAC-SHA512'
        }
        
        if encryption_type.lower() == 'none':
            return 'No-Encryption'
        else:
            return crackable_encryptions.get(encryption_type.lower(), '')
    return None

def crack_jwt_encryption(jwt_token: str) -> None:
    """
    Checks if the encryption type of a JWT (JSON Web Token) is crackable and prints the corresponding hashcat or john command.

    Args:
        jwt (str): The JWT token as a string.

    Returns:
        None
    """
    
    # Check if the JWT encryption is crackable
    jwt_encryption = is_crackable_encryption(jwt_token)
    if jwt_encryption:
        if jwt_encryption == 'No-Encryption':
            print("[bold red][!] JWT using no encryption.[/bold red][yellow] This means you can change anything in the token you want![/yellow]")
        else:
            print("[bold red][!] JWT is using pre-shared key encryption.[/bold red][yellow] We might be able to crack the key used to sign it![/yellow]")
            print(f"[yellow][+] john jwt.txt --format={jwt_encryption}[/yellow]")
            print(f"[yellow][+] hashcat -a 0 -m 16500 {jwt_token} /usr/share/wordlists/[/yellow]")
    else:
        print(f"[bold green][+] JWT using asymmetric encryption [/bold green]{get_jwt_encryption_type(jwt_token)}[bold green] aka not crackable[/bold green]")

def is_jwt_required(request: str, original_response: httpx.Response, verbose: bool, use_http: bool, proxy: Optional[Dict[str, str]] = None) -> bool:
    """
    Checks if a JWT (JSON Web Token) is required for the given request.

    Args:
        request (str): The original HTTP request.
        original_response (httpx.Response): The original response received from the server.
        verbose (bool): Flag to print verbose output.
        use_http (bool): Flag indicating whether to use HTTP instead of HTTPS.
        proxy (Optional[Dict[str, str]]): A dictionary of proxies to use for the request.

    Returns:
        bool: True if the JWT is required, False otherwise.
    """
    modified_request = remove_jwt_from_request(request)
    modified_request = add_jwtmap_cookie(modified_request, "No-JWT-Request")
    modified_response, _ = execute_request(modified_request, use_http, proxy)
    
    if modified_response is not None:
        print_request_response(modified_request, modified_response, verbose)

        if original_response.status_code != modified_response.status_code:
            if verbose:
                print(f"Response codes do not match: {original_response.status_code} != {modified_response.status_code}")
            return True

        if 'Content-Length' in modified_response.headers and 'Content-Length' in original_response.headers:
            if modified_response.headers['Content-Length'] != original_response.headers['Content-Length']:
                if verbose:
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

def is_jwt_signature_checked(request: str, original_response: httpx.Response, verbose: bool, use_http: bool, proxy: Optional[Dict[str, str]] = None) -> bool:
    """
    Checks if the signature of a JWT (JSON Web Token) is verified by the server.

    Args:
        request (str): The original HTTP request.
        original_response (httpx.Response): The original response received from the server.
        verbose (bool): Flag to print verbose output.
        use_http (bool): Flag indicating whether to use HTTP instead of HTTPS.
        proxy (Optional[Dict[str, str]]): A dictionary of proxies to use for the request.

    Returns:
        bool: True if the JWT signature is checked, False otherwise.
    """

    jwt = get_jwt_from_request(request)

    if jwt is not None:
        invalid_jwt = remove_signature_from_jwt(jwt)
        modified_request = replace_jwt_in_request(request, invalid_jwt)
        modified_request = add_jwtmap_cookie(modified_request, "Signature-checked-request")
        modified_response, _ = execute_request(modified_request, use_http, proxy)
    else:
        modified_response = None

    if modified_response is not None:
        print_request_response(modified_request, modified_response, verbose)

        if original_response.status_code != modified_response.status_code:
            if verbose:
                print(f"JWT signature check: Response codes do not match: {original_response.status_code} != {modified_response.status_code}")
            return True

        if 'Content-Length' in modified_response.headers and 'Content-Length' in original_response.headers:
            if modified_response.headers['Content-Length'] != original_response.headers['Content-Length']:
                if verbose:
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

def main() -> None:
    parser = argparse.ArgumentParser(description="Execute curl command or HTTP request from a file.")
    parser.add_argument("path", help="Path to the file or directory containing the curl command(s) or HTTP request(s).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to see the request and response.")
    parser.add_argument("--http", action="store_true", help="Check HTTP, Default is HTTPS.")
    parser.add_argument("--proxy", help="Proxy server to use for requests in the format http://user:pass@host:port")

    # New flag for AI check (OpenAI/LLM)
    parser.add_argument("--ai", action="store_true", help="Enable AI/LLM analysis using OpenAI or other models.")

    # Parse arguments
    args = parser.parse_args()

    # Example logic based on the --ai flag
    if args.ai:
        print("AI/LLM analysis will be performed on the input.")

    args = parser.parse_args()

    # Check if the input path is a JWT token
    if is_jwt(args.path):
        if args.ai:
            # Perform AI analysis of the JWT token
            asyncio.run(process_and_analyze_jwt(args.path, args.verbose))
        else:
            process_jwt(args.path, args.verbose)
         # Check if the JWT encryption is crackable
        jwt_encryption = is_crackable_encryption(args.path)
        if jwt_encryption:
            print("\n[bold white]Security Checks...[/bold white]\n")
            crack_jwt_encryption(args.path)
        return
    
    if os.path.isdir(args.path):
        # If it's a directory, iterate over each file in the directory
        for filename in os.listdir(args.path):
            file_path = os.path.join(args.path, filename)
            if os.path.isfile(file_path):  # Ensuring it's a file
                print(f"\nProcessing {file_path}...")
                request_content = read_request_file(file_path)
                process_request(request_content, args.ai, args.verbose, args.http, args.proxy)
    elif os.path.isfile(args.path):
        # If it's a single file, process it directly
        request_content = read_request_file(args.path)
        process_request(request_content, args.ai, args.verbose, args.http, args.proxy)
    else:
        print(f"The specified file or directory does not exist: {args.path}")



if __name__ == "__main__":
    main()


