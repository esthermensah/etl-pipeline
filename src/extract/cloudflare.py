from .base import Extractor
import pandas as pd
import requests

class CloudflareExtractor(Extractor):
    def fetch_data(self, endpoint: str, params: dict) -> dict:
        url = f"{self.config['base_url']}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json().get("result", {})
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch {endpoint}: {e}")
            return {}

    def process_data(self, data: dict, value_key: str) -> pd.DataFrame:
        # Implement Cloudflare-specific processing (e.g., handle country codes)
        pass