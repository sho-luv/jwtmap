import os
import sys
import asyncio
import argparse
from dotenv import load_dotenv
from openai import AsyncOpenAI

# Load environment variables from .env file
load_dotenv()

# Get the OpenAI API key from the environment variables
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("No OPENAI_API_KEY found in environment variables.")

# Check if rich is installed for enhanced printing
try:
    from rich.console import Console
    from rich import print
    console = Console()
except ImportError:
    console = None

# Initialize OpenAI client
client = AsyncOpenAI(api_key=api_key)

async def ask_openai(question: str, context: str) -> str:
    """
    Asks OpenAI a question within a given context and returns the response.

    Args:
        question (str): The question to ask OpenAI.
        context (str): The context in which the question is being asked.

    Returns:
        str: The response from OpenAI.
    """
    response = await client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": f"{context}\n\nQuestion: {question}",
            }
        ],
        model="gpt-3.5-turbo",
    )
    
    # Extract and return the response content
    return response.choices[0].message.content

def print_response(response: str) -> None:
    """
    Prints the response either with rich if available or using standard print.

    Args:
        response (str): The response content to print.
    """
    if console:
        console.print(response)
    else:
        print(response)

def main() -> None:
    """
    Main entry point of the script. Parses arguments and runs the OpenAI query.
    """
    parser = argparse.ArgumentParser(description="Ask OpenAI a question with context.")
    parser.add_argument("question", type=str, help="The question to ask OpenAI.")
    parser.add_argument("context", type=str, help="The context for the question.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Run the ask_openai function with the provided arguments and print the response
    response = asyncio.run(ask_openai(args.question, args.context))
    print_response(response)

if __name__ == "__main__":
    main()