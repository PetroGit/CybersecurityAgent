import os
import time
from mistralai.client import Mistral

client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])

start = time.monotonic()

try:
    response = client.chat.complete(
        model="mistral-large-4",
        messages=[
            {
                "role": "user",
                "content": "Reply with exactly OK.",
            }
        ],
    )

    print("SUCCESS")
    print("Latency:", round(time.monotonic() - start, 2), "seconds")
    print(response.choices[0].message.content)

except Exception as exc:
    print("FAILED")
    print("Exception:", type(exc).__name__)
    print("Latency:", round(time.monotonic() - start, 2), "seconds")