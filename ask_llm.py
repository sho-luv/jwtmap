import os
import sys
import asyncio
import argparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Resolve LLM configuration from environment variables (read at import, used lazily)
model = os.getenv("LLM_MODEL", "gpt-4o-mini")

# Check if rich is installed for enhanced printing
try:
    from rich.console import Console
    from rich import print
    console = Console()
except ImportError:
    console = None

# Client is created lazily on first call to ask_llm()
_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client

    from openai import AsyncOpenAI

    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("LLM_BASE_URL")

    if not api_key:
        raise ValueError(
            "No LLM API key found. Set LLM_API_KEY or OPENAI_API_KEY in your environment or .env file.\n"
            "Optionally set LLM_BASE_URL and LLM_MODEL for non-OpenAI providers."
        )

    client_kwargs = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    _client = AsyncOpenAI(**client_kwargs)
    return _client


async def ask_llm(question: str, context: str) -> str:
    """
    Sends a question with context to the configured LLM and returns the response.

    Works with any OpenAI-compatible API endpoint (OpenAI, Ollama, LM Studio,
    vLLM, Groq, Together, etc.) by setting environment variables:
        LLM_API_KEY   - API key (falls back to OPENAI_API_KEY)
        LLM_BASE_URL  - API base URL (omit for OpenAI default)
        LLM_MODEL     - Model name (default: gpt-4o-mini)

    Args:
        question (str): The question to ask.
        context (str): The context in which the question is being asked.

    Returns:
        str: The response from the LLM.
    """
    client = _get_client()
    response = await client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": f"{context}\n\nQuestion: {question}",
            }
        ],
        model=model,
    )

    return response.choices[0].message.content


def print_response(response: str) -> None:
    if console:
        console.print(response)
    else:
        print(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ask an LLM a question with context.")
    parser.add_argument("question", type=str, help="The question to ask.")
    parser.add_argument("context", type=str, help="The context for the question.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    response = asyncio.run(ask_llm(args.question, args.context))
    print_response(response)


if __name__ == "__main__":
    main()
