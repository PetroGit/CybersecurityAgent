from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:11434/v1",
    api_key="ollama"
)

response = client.chat.completions.create(
    model="ministral-3:3b",
    messages=[
        {
            "role": "system",
            "content": (
                "You are an application security engineer. "
                "Analyse Python vulnerabilities and propose "
                "secure patches and regression tests."
            )
        },
        {
            "role": "user",
            "content": "Review this Python code for security weaknesses."
        }
    ]
)

print(response.choices[0].message.content)