import os
from openai import AzureOpenAI
from dotenv import load_dotenv

print("Attempting to connect to Azure OpenAI...")

# Load variables from .env file
load_dotenv()

try:
    # Get configuration from environment variables
    azure_endpoint = str(os.getenv("AZURE_OPENAI_ENDPOINT"))
    api_key = str(os.getenv("AZURE_OPENAI_API_KEY"))
    deployment_name = str(os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"))
    api_version = "2023-12-01-preview"

    if not all([azure_endpoint, api_key, deployment_name]):
        raise ValueError("One or more environment variables are missing.")

    print(f"Endpoint: {azure_endpoint}")
    print(f"Deployment: {deployment_name}")

    # Initialize the client
    client = AzureOpenAI(
        api_key=api_key,
        api_version=api_version,
        azure_endpoint=azure_endpoint
    )

    # Make a simple, lightweight API call
    response = client.chat.completions.create(
        model=deployment_name,
        messages=[{"role": "user", "content": "Hello world"}],
        max_tokens=5
    )

    print("\nSUCCESS! Connection established and received a response.")
    print("Response:", response.choices[0].message.content)

except Exception as e:
    print(f"\nFAILURE! An error occurred: {e}")