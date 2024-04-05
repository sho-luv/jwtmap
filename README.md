# JWTMap

JWTMap is a comprehensive tool designed to check for vulnerabilities in JSON Web Tokens (JWT). Utilizing advanced techniques, it automates the process of detecting and exploiting known vulnerabilities in JWT implementations. Whether you're performing security assessments or just curious about the security of your JWT tokens, JWTMap offers a powerful set of functionalities to help you uncover potential weaknesses.

## Features

- **JWT Vulnerability Scanning:** Automatically identifies common vulnerabilities in JWT implementations.
- **Encryption Type Detection:** Determines the encryption type (algorithm) used in a JWT.
- **Signature Verification:** Checks whether the JWT signature is properly verified by the server.
- **Token Invalidity Simulation:** Tests how systems react to modified or invalidated JWTs.
- **Command Line Interface:** Easy-to-use CLI for quick and efficient security assessments.
- **Verbose Mode:** Provides detailed request and response data for in-depth analysis.

## Installation

Before installing JWTMap, ensure you have Python 3.x installed on your system. You can then install JWTMap by cloning the repository:

```
git clone https://github.com/yourusername/jwtmap.git
cd jwtmap
```

JWTMap requires several dependencies, which can be installed via pip:

```
pip install -r requirements.txt
```

## Usage

To use JWTMap, you can either pass a curl command or an HTTP request from a file. Here's how to get started:

```
python jwtmap.py [options] <file>
```

Options:

- `-v`, `--verbose`: Enable verbose mode to see detailed request and response information.
- `--http`: Use HTTP instead of HTTPS for requests.

Example:
```
python jwtmap.py --verbose --http request.txt
```

The `request.txt` file should contain a valid curl command or HTTP request with the JWT you wish to test.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- Inspired by the functionality and design of [sqlmap](http://sqlmap.org/).
- Thanks to all contributors who have helped to build and refine this tool.
