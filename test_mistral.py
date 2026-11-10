
import os
from mistralai import Mistral

api_key = os.environ["MISTRAL_API_KEY"]

client = Mistral(api_key=api_key)

<<<<<<< HEAD
with Mistral(api_key=api_key) as client:
    response = client.chat.complete(
        model="mistral-large-4",
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
=======
response = client.chat.complete(
    model="YOUR_MISTRAL_LARGE_4_MODEL_ID",
    messages=[
        {
            "role": "system",
            "content": (
                "You are a cybersecurity assistant. "
                "Provide accurate, concise technical answers."
            )
        },
        {
            "role": "user",
            "content": "Explain log monitoring in one sentence."
        }
    ]
)

content = response.choices[0].message.content

if isinstance(content, str):
    final_answer = content
else:
    final_answer = "\n".join(
        chunk.text
        for chunk in content
        if getattr(chunk, "type", None) == "text"
        and getattr(chunk, "text", None)
>>>>>>> 9eb05decb0ddb65bd954c7e4633a689ad410c107
    )

print("\n=== MISTRAL RESPONSE ===")
print(final_answer)

