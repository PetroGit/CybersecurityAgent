

import os
from mistralai.client import Mistral

api_key = os.environ["MISTRAL_API_KEY"]

client = Mistral(api_key=api_key)

response = client.chat.complete(
    model="mistral-large-4",
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
        and isinstance(getattr(chunk, "text", None), str)
    )

print("\n=== MISTRAL FINAL ANSWER ===")
print(final_answer)



if __name__ == "__main__":
    main()
