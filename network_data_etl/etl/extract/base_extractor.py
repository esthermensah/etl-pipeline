import httpx
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()
API_BASE_URL = os.getenv("API_BASE_URL")
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

async def fetch(session, endpoint, params):
    url = f"{API_BASE_URL}/{endpoint}"
    try:
        response = await session.get(url, params=params)
        response.raise_for_status()
        return response.json().get("result", {})
    except Exception as e:
        print(f"Fetch failed for {endpoint}: {e}")
        return None

async def extract_datasets(configs):
    async with httpx.AsyncClient(headers=HEADERS) as session:
        tasks = [
            fetch(session, ds["endpoint"], ds.get("params", {}))
            for ds in configs
        ]
        return await asyncio.gather(*tasks)
