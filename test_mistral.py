

import os
from mistralai import Mistral

# Mistral API configuration
API_KEY = os.getenv("MISTRAL_API_KEY")

# Use the exact Mistral Large 4 model ID available
# in your Mistral account.
MODEL = os.getenv("MISTRAL_MODEL")

if not API_KEY:
    raise RuntimeError("MISTRAL_API_KEY is not configured")

if not MODEL:
    raise RuntimeError("MISTRAL_MODEL is not configured")

def extract_final_answer(content):
    """Extract final text and exclude reasoning chunks."""
    if isinstance(content, str):
        return content

    if not content:
        return ""

    return "\n".join(
        chunk.text
        for chunk in content
        if getattr(chunk, "type", None) == "text"
        and isinstance(getattr(chunk, "text", None), str)
    )


def main():
    print(f"Connecting to Mistral AI: {MODEL}")

    with Mistral(api_key=API_KEY) as client:
        response = client.chat.complete(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert cybersecurity assistant. "
                        "Provide accurate, concise, technical answers."
                    )
                },
                {
                    "role": "user",
                    "content": "Explain log monitoring in one sentence."
                }
            ]
        )

    answer = extract_final_answer(
        response.choices[0].message.content
    )

    if not answer:
        raise RuntimeError("No final text returned by Mistral")

    print("\n=== MISTRAL FINAL ANSWER ===")
    print(answer)


if __name__ == "__main__":
    main()
