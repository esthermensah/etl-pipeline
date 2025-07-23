import os

base_structure = {
    "network_data_etl": {
        ".env": "CLOUDFLARE_API_TOKEN=your_token_here\nAPI_BASE_URL=https://api.cloudflare.com/client/v4/radar",
        ".gitignore": ".env\n__pycache__/\n*.pyc\ndata/\n",
        "README.md": "# Network Data ETL\n\nAn ETL pipeline for Cloudflare Radar and other network datasets.",
        "requirements.txt": "\n".join([
            "pandas",
            "httpx",
            "pyyaml",
            "python-dotenv",
            "pycountry"
        ]),
        "pyproject.toml": "",  # optional; leave empty if not using poetry/pipenv
        "main.py": '''
import yaml
import asyncio
from etl.extract.base_extractor import extract_datasets
from etl.transform.processors import process_top_locations
from etl.load.to_csv import save

def load_config(path="etl/config/cloudflare_config.yaml"):
    with open(path, 'r') as f:
        return yaml.safe_load(f)["datasets"]

async def main():
    configs = load_config()
    raw_results = await extract_datasets(configs)

    for config, raw in zip(configs, raw_results):
        if raw:
            df = process_top_locations(raw, config["value_key"])
            save(df, config["name"])

if __name__ == "__main__":
    asyncio.run(main())
''',
        "notebooks": {
            "dev_exploration.ipynb": ""
        },
        "etl": {
            "__init__.py": "",
            "config": {
                "cloudflare_config.yaml": '''
datasets:
  - name: http_requests_total
    endpoint: http/top/locations
    value_key: http_requests_total
  - name: ipv4_http_requests
    endpoint: http/top/locations/ip_version/ipv4
    value_key: ipv4_http_requests
    params:
      metric: ip_version/IPv4
'''
            },
            "extract": {
                "__init__.py": "",
                "base_extractor.py": '''
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
'''
            },
            "transform": {
                "processors.py": '''
import pandas as pd

def process_top_locations(data, value_key):
    if not data or "main" not in data:
        return pd.DataFrame()

    records = []
    for item in data["main"]:
        records.append({
            "country_code": item.get("clientCountryAlpha2", "Unknown"),
            "country_name": item.get("clientCountryName", "Unknown"),
            value_key: item.get("value", 0)
        })

    return pd.DataFrame(records)
'''
            },
            "load": {
                "to_csv.py": '''
import os
import pandas as pd

def save(df, name, output_dir="data"):
    os.makedirs(output_dir, exist_ok=True)
    df.to_csv(f"{output_dir}/{name}.csv", index=False)
'''
            },
            "utils": {
                "logger.py": '''
import logging

def get_logger(name="etl"):
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )
    return logging.getLogger(name)
''',
                "validators.py": '''
# Placeholder for future validation logic (e.g. using pandera or pydantic)
'''
            }
        }
    }
}

def create_structure(root_path, structure):
    for name, content in structure.items():
        path = os.path.join(root_path, name)
        if isinstance(content, dict):
            os.makedirs(path, exist_ok=True)
            create_structure(path, content)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content.strip() + "\n")

create_structure(".", base_structure)
print("✅ Project scaffold created at ./network_data_etl")
