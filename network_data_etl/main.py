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
