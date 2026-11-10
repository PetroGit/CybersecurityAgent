import os
from mistralai.client import Mistral

api_key = os.getenv("MISTRAL_API_KEY")

if not api_key:
    raise RuntimeError("MISTRAL_API_KEY is not set")

with Mistral(api_key=api_key) as client:
    response = client.chat.complete(
        model="mistral-small-latest",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity assistant."
            },
            {
                "role": "user",
                "content": "Explain Log Monitoring in one sentence."
            }
        ]
    )

    print(response.choices[0].message.content)
