"""
THIS SCRIPT CREATES A DATA WAREHOUSE FOR ALL COUNTRY-SPECIFIC CLOUDFLARE RADAR DATASETS
AND EXTRACTS ADDITIONAL DATASETS INCLUDING ATTACKS AND DEVICE TYPES
"""

import os
import requests
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional
import logging
import pycountry
from credentials import API_TOKEN  #  this is defined in credentials.py
from cloudflare import Cloudflare

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
API_BASE_URL = "https://api.cloudflare.com/client/v4/radar"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WAREHOUSE_DIR = os.path.join(SCRIPT_DIR, "../all_datasets/cloudflare_data")
MASTER_WAREHOUSE_FILE = os.path.join(WAREHOUSE_DIR, "cloudflare_master_warehouse.csv")
MASTER_WAREHOUSE_ISO3_FILE = os.path.join(WAREHOUSE_DIR, "cloudflare_master_warehouse_iso3.csv")
AFRICAN_COUNTRIES_FILE = os.path.join(WAREHOUSE_DIR, "cloudflare_african_countries.csv")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}
DEFAULT_PARAMS = {
    "dateRange": "7d",
    "limit": 200,
    "format": "json",
    "name": "main"
}

AFRICAN_COUNTRIES_ISO3 = [
    "DZA", "AGO", "BEN", "BWA", "BFA", "BDI", "CMR", "CPV", "CAF", "TCD", "COM", "COG",
    "COD", "DJI", "EGY", "GNQ", "ERI", "SWZ", "ETH", "GAB", "GMB", "GHA", "GIN", "GNB",
    "CIV", "KEN", "LSO", "LBR", "LBY", "MDG", "MWI", "MLI", "MRT", "MUS", "MAR", "MOZ",
    "NAM", "NER", "NGA", "RWA", "STP", "SEN", "SYC", "SLE", "SOM", "ZAF", "SSD", "SDN",
    "TZA", "TGO", "TUN", "UGA", "ZMB", "ZWE"
]

def ensure_directory_exists():
    """Create warehouse directory if it doesn't exist."""
    os.makedirs(WAREHOUSE_DIR, exist_ok=True)

def save_to_csv(df: pd.DataFrame, filename: str) -> None:
    """Save DataFrame to CSV with error handling."""
    try:
        filepath = os.path.join(WAREHOUSE_DIR, f"{filename}.csv")
        df.to_csv(filepath, index=False, encoding='utf-8')
        logging.info(f"Saved data to: {filepath}")
    except Exception as e:
        logging.error(f"Error saving {filename}: {str(e)}")

def fetch_api_data(endpoint: str, params: Dict = {}, method: str = "GET") -> Optional[Dict]:
    """Generic API fetch function with error handling."""
    url = f"{API_BASE_URL}/{endpoint}"
    full_params = {**DEFAULT_PARAMS, **params}
    logging.debug(f"Request URL: {url}")
    logging.debug(f"Request Params: {full_params}")
    try:
        response = requests.request(method, url, headers=HEADERS, params=full_params)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            logging.error(f"API error for {endpoint}: {data.get('errors', 'Unknown error')}")
            return None
        return data.get("result", {})
    except requests.RequestException as e:
        logging.error(f"Failed to fetch {endpoint}: {str(e)} - Response: {response.text if 'response' in locals() else 'No response'}")
        return None

def process_top_locations_data(data: Dict, value_key: str, name_key: str = "main") -> pd.DataFrame:
    """Process top locations data (country-level), ensuring Namibia is NA."""
    if not data or name_key not in data:
        logging.warning(f"No '{name_key}' data in response for {value_key}")
        return pd.DataFrame()
    processed = []
    for item in data.get(name_key, []):
        country_code = item.get("clientCountryAlpha2")
        country_name = item.get("clientCountryName")
        if not country_code or pd.isna(country_code):
            if country_name and country_name.lower() == "namibia":
                country_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (was missing)")
            elif country_name:
                try:
                    country = pycountry.countries.search_fuzzy(country_name)[0]
                    country_code = country.alpha_2
                    logging.info(f"Inferred country_code_iso2 {country_code} for {country_name}")
                except LookupError:
                    country_code = "Unknown"
        processed.append({
            "country_code_iso2": country_code if country_code else "Unknown",
            "country_name": country_name,
            value_key: item.get("value")
        })
    return pd.DataFrame(processed)

def process_quality_data(data: Dict) -> pd.DataFrame:
    """Process internet quality data (country-level), retaining all metrics."""
    if not data or "top_0" not in data:
        logging.warning("No 'top_0' data in response for internet quality")
        return pd.DataFrame()
    processed = []
    for item in data.get("top_0", []):
        country_code = item.get("clientCountryAlpha2")
        country_name = item.get("clientCountryName")
        if not country_code or pd.isna(country_code):
            if country_name and country_name.lower() == "namibia":
                country_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (was missing)")
            elif country_name:
                try:
                    country = pycountry.countries.search_fuzzy(country_name)[0]
                    country_code = country.alpha_2
                    logging.info(f"Inferred country_code_iso2 {country_code} for {country_name}")
                except LookupError:
                    country_code = "Unknown"
        processed.append({
            "country_code_iso2": country_code if country_code else "Unknown",
            "country_name": country_name,
            "bandwidth_download": item.get("bandwidthDownload"),
            "bandwidth_upload": item.get("bandwidthUpload"),
            "latency_idle": item.get("latencyIdle"),
            "latency_loaded": item.get("latencyLoaded"),
            "jitter_idle": item.get("jitterIdle"),
            "jitter_loaded": item.get("jitterLoaded")
        })
    return pd.DataFrame(processed)

def process_layer3_attacks_data(data: Dict, value_key: str, name_key: str = "top_0") -> pd.DataFrame:
    """Process Layer 3 attacks data with origin or target country, aggregating attacks per country."""
    if not data or name_key not in data:
        logging.warning(f"No '{name_key}' data in response for {value_key}")
        return pd.DataFrame()
    
    aggregated = {}
    is_target = "targetCountryAlpha2" in data.get(name_key, [{}])[0]
    country_key = "targetCountryAlpha2" if is_target else "originCountryAlpha2"
    name_key_field = "targetCountryName" if is_target else "originCountryName"
    
    for item in data.get(name_key, []):
        country_code = item.get(country_key)
        country_name = item.get(name_key_field)
        attack_value = item.get("value", 0)
        
        if not country_code and country_name and country_name.lower() == "namibia":
            country_code = "NA"
            logging.info(f"Manually set country_code_iso2 to NA for Namibia")
        
        country_code = country_code if country_code else "Unknown"
        
        if country_code in aggregated:
            aggregated[country_code][value_key] += attack_value
        else:
            aggregated[country_code] = {
                "country_code_iso2": country_code,
                "country_name": country_name,
                value_key: attack_value
            }
    
    return pd.DataFrame(list(aggregated.values()))

def process_layer7_attacks_data(data: Dict, value_key: str, name_key: str = "top_0") -> pd.DataFrame:
    """Process Layer 7 attacks data with origin or target countries, aggregating attacks per country."""
    if not data or name_key not in data:
        logging.warning(f"No '{name_key}' data in response for {value_key}")
        return pd.DataFrame()
    
    has_origin = "originCountryAlpha2" in data.get(name_key, [{}])[0]
    has_target = "targetCountryAlpha2" in data.get(name_key, [{}])[0]
    
    if has_origin and not has_target:
        aggregated = {}
        for item in data.get(name_key, []):
            country_code = item.get("originCountryAlpha2")
            country_name = item.get("originCountryName")
            attack_value = item.get("value", 0)
            
            if not country_code and country_name and country_name.lower() == "namibia":
                country_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (origin)")
            
            country_code = country_code if country_code else "Unknown"
            
            if country_code in aggregated:
                aggregated[country_code][value_key] += attack_value
            else:
                aggregated[country_code] = {
                    "country_code_iso2": country_code,
                    "country_name": country_name,
                    value_key: attack_value
                }
        return pd.DataFrame(list(aggregated.values()))
    
    elif has_target and not has_origin:
        aggregated = {}
        for item in data.get(name_key, []):
            country_code = item.get("targetCountryAlpha2")
            country_name = item.get("targetCountryName")
            attack_value = item.get("value", 0)
            
            if not country_code and country_name and country_name.lower() == "namibia":
                country_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (target)")
            
            country_code = country_code if country_code else "Unknown"
            
            if country_code in aggregated:
                aggregated[country_code][value_key] += attack_value
            else:
                aggregated[country_code] = {
                    "country_code_iso2": country_code,
                    "country_name": country_name,
                    value_key: attack_value
                }
        return pd.DataFrame(list(aggregated.values()))
    
    else:
        origin_aggregated = {}
        target_aggregated = {}
        for item in data.get(name_key, []):
            origin_code = item.get("originCountryAlpha2")
            origin_name = item.get("originCountryName")
            target_code = item.get("targetCountryAlpha2")
            target_name = item.get("targetCountryName")
            attack_value = item.get("value", 0)
            
            if not origin_code and origin_name and origin_name.lower() == "namibia":
                origin_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (origin)")
            if not target_code and target_name and target_name.lower() == "namibia":
                target_code = "NA"
                logging.info(f"Manually set country_code_iso2 to NA for Namibia (target)")
            
            origin_code = origin_code if origin_code else "Unknown"
            target_code = target_code if target_code else "Unknown"
            
            if origin_code in origin_aggregated:
                origin_aggregated[origin_code]["layer7_top_origin_attacks"] += attack_value
            else:
                origin_aggregated[origin_code] = {
                    "country_code_iso2": origin_code,
                    "country_name": origin_name,
                    "layer7_top_origin_attacks": attack_value
                }
            
            if target_code in target_aggregated:
                target_aggregated[target_code]["layer7_top_target_attacks"] += attack_value
            else:
                target_aggregated[target_code] = {
                    "country_code_iso2": target_code,
                    "country_name": target_name,
                    "layer7_top_target_attacks": attack_value
                }
        
        return {
            "origin": pd.DataFrame(list(origin_aggregated.values())),
            "target": pd.DataFrame(list(target_aggregated.values()))
        }
    
def process_outages_data(data: dict):
    if not data or "annotations" not in data:
        logging.warning("No 'annotations' data in response")
        return pd.DataFrame()
    processed = []
    for annotation in data.get("annotations", []):
        for loc_code in annotation.get("locations", []):
            # Find matching location details for the name
            loc_details = next((loc for loc in annotation.get("locationsDetails", []) if loc["code"] == loc_code), {"name": "Unknown"})
            processed.append({
                "country_code_iso2": loc_code,
                "country_name": loc_details.get("name", "Unknown"),
                "outages": 1  # Count each outage event
            })
    df = pd.DataFrame(processed).groupby(["country_code_iso2", "country_name"], as_index=False).sum()
    logging.debug(f"Processed {len(df)} unique countries with outages")
    return df


def process_outages_location(data: List[Dict]) -> pd.DataFrame:
    """Process outage annotations into a DataFrame with clean country info."""
    if not data:
        logging.warning("No outage data provided.")
        return pd.DataFrame()

    processed = []
    for item in data:
        country_code = item.get("clientCountryAlpha2")
        country_name = item.get("clientCountryName")

        if not country_code and country_name:
            try:
                country = pycountry.countries.search_fuzzy(country_name)[0]
                country_code = country.alpha_2
                logging.info(f"Inferred country code {country_code} for {country_name}")
            except LookupError:
                country_code = "Unknown"

        processed.append({
            "country_code": country_code or "Unknown",
            "country_name": country_name or "Unknown",
            "value": item.get("value")
        })

    return pd.DataFrame(processed)


# -----------------------Extraction Functions-----------------------

def extract_outages_location(date_range: str = "300d", filename: str = "outages_location.csv"):
    url = "https://api.cloudflare.com/client/v4/radar/annotations/outages/locations"
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    params = {"dateRange": date_range}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    logging.debug(f"API response: {data}")
    if not data.get("success"):
        logging.error(f"API Error: {data.get('errors')}")
        return
    annotations = data.get("result", {}).get("annotations", [])
    logging.debug(f"Annotations: {annotations}")
    if not annotations:
        logging.warning("No annotations found in API response")
        return
    df = process_outages_location(annotations)
    df = df.rename(columns={"country_code": "country_code_iso2"})  # Rename column for consistency
    if df.empty:
        logging.warning("Processed DataFrame is empty")
        return
    file_path = os.path.join(WAREHOUSE_DIR, filename)
    df.to_csv(file_path, index=False)
    logging.info(f"Outages location data saved to {file_path}")




def extract_outages():
    params = {"dateRange": "300d", "limit": 500}  
    data = fetch_api_data("annotations/outages/", params)
    if data:
        df = process_outages_data(data)
        save_to_csv(df, "outages")


def extract_http_requests():
    """Extract country-specific HTTP request data."""
    endpoints = {
        "http_requests_total": ("http/top/locations", {}, "http_requests_total"),
        "ipv4_http_requests": ("http/top/locations/ip_version/ipv4", {"metric": "ip_version/IPv4"}, "ipv4_http_requests"),
        "ipv6_http_requests": ("http/top/locations/ip_version/ipv6", {"metric": "ip_version/IPv6"}, "ipv6_http_requests"),
        "http_by_tls_1_3": ("http/top/locations/tls_version/tlsv1_3", {"metric": "tls_version/TLSv1_3"}, "tls_1_3_requests"),
        "http_by_tls_1_2": ("http/top/locations/tls_version/tlsv1_2", {"metric": "tls_version/TLSv1_2"}, "tls_1_2_requests"),
        "http_by_bots": ("http/top/locations/bot_class/bot", {"metric": "bot_class/bot"}, "bot_requests"),
        "http_by_humans": ("http/top/locations/bot_class/human", {"metric": "bot_class/human"}, "human_requests")
    }
    for name, (endpoint, params, value_key) in endpoints.items():
        data = fetch_api_data(endpoint, params)
        if data:
            df = process_top_locations_data(data, value_key)
            save_to_csv(df, name)

def extract_network_traffic():
    """Extract country-specific network traffic data."""
    data = fetch_api_data("netflows/top/locations", {})
    if data:
        df = process_top_locations_data(data, "network_traffic")
        save_to_csv(df, "netflows")

def extract_dns_queries():
    """Extract country-specific DNS queries data."""
    data = fetch_api_data("dns/top/locations", {})
    if data:
        df = process_top_locations_data(data, "dns_queries")
        save_to_csv(df, "dns_queries")

def extract_internet_quality():
    """Extract country-specific internet quality data with all metrics."""
    params = {"metric": "bandwidth,latency,DNS", "aggInterval": "1h", "name": "top_0"}
    data = fetch_api_data("quality/speed/top/locations", params)
    if data:
        df = process_quality_data(data)
        save_to_csv(df, "internet_quality")

def extract_top_domains():
    """Extract country-specific top domains data."""
    data = fetch_api_data("datasets/top/domains/locations", {})
    if data:
        df = process_top_locations_data(data, "top_domains_traffic")
        save_to_csv(df, "top_domains_traffic")

def extract_email_security():
    """Extract country-specific email security data."""
    data = fetch_api_data("email/security/top/locations/threats", {})
    if data:
        df = process_top_locations_data(data, "email_threats")
        save_to_csv(df, "email_threats")

def extract_tcp_resets_timeouts():
    """Extract country-specific TCP resets and timeouts data."""
    data = fetch_api_data("tcp_resets_timeouts/top/locations", {})
    if data:
        df = process_top_locations_data(data, "tcp_resets_timeouts")
        save_to_csv(df, "tcp_resets_timeouts")

def extract_browser_usage():
    """Extract country-specific browser usage data."""
    endpoints = {
        "browser_chrome": ("http/top/locations/browser_family/chrome", {"metric": "browser/chrome"}, "chrome_requests"),
        "browser_firefox": ("http/top/locations/browser_family/firefox", {"metric": "browser/firefox"}, "firefox_requests"),
        "browser_safari": ("http/top/locations/browser_family/safari", {"metric": "browser/safari"}, "safari_requests"),
        "browser_edge": ("http/top/locations/browser_family/edge", {"metric": "browser/edge"}, "edge_requests")
    }
    for name, (endpoint, params, value_key) in endpoints.items():
        data = fetch_api_data(endpoint, params)
        if data:
            df = process_top_locations_data(data, value_key)
            save_to_csv(df, name)

def extract_os_usage():
    """Extract country-specific OS usage data."""
    endpoints = {
        "os_windows": ("http/top/locations/os/windows", {"metric": "os/windows"}, "windows_requests"),
        "os_macos": ("http/top/locations/os/macos", {"metric": "os/macos"}, "macos_requests"),
        "os_linux": ("http/top/locations/os/linux", {"metric": "os/linux"}, "linux_requests"),
        "os_android": ("http/top/locations/os/android", {"metric": "os/android"}, "android_requests"),
        "os_ios": ("http/top/locations/os/ios", {"metric": "os/ios"}, "ios_requests")
    }
    for name, (endpoint, params, value_key) in endpoints.items():
        data = fetch_api_data(endpoint, params)
        if data:
            df = process_top_locations_data(data, value_key)
            save_to_csv(df, name)


def extract_bot_class_data():
    """Extract HTTP requests by bot class from /radar/http/top/locations/bot_class/{bot_class}."""
    bot_classes = ["likely_automated", "likely_human"]
    for bot_class in bot_classes:
        endpoint = f"http/top/locations/bot_class/{bot_class}"
        params = {"name": "top_0"}
        data = fetch_api_data(endpoint, params)
        if data and "top_0" in data:
            df = process_top_locations_data(data, f"{bot_class}_requests", name_key="top_0")
            save_to_csv(df, f"http_by_{bot_class}")

def extract_layer7_top_attacks_split():
    """Extract top Layer 7 attacks, splitting into origin and target CSVs."""
    data = fetch_api_data("attacks/layer7/top/attacks", {"name": "top_0"})
    if data:
        result = process_layer7_attacks_data(data, "layer7_top_attacks")
        if isinstance(result, dict) and "origin" in result and "target" in result:
            save_to_csv(result["origin"], "layer7_origin_attacks_from_top")
            save_to_csv(result["target"], "layer7_target_attacks_from_top")
        else:
            logging.error("Failed to split layer7_top_attacks into origin and target")

def extract_layer3_top_origin_attacks():
    """Extract top Layer 3 attacks with origin country."""
    data = fetch_api_data("attacks/layer3/top/attacks", {"name": "top_0"})
    if data:
        df = process_layer3_attacks_data(data, "layer3_attacks")
        save_to_csv(df, "layer3_top_origin_attacks")

def extract_layer7_target_locations():
    """Extract Layer 7 attacks by target locations."""
    data = fetch_api_data("attacks/layer7/top/locations/target", {"name": "top_0"})
    if data:
        df = process_layer7_attacks_data(data, "layer7_target_attacks")
        save_to_csv(df, "layer7_target_attacks")

def extract_layer3_target_locations():
    """Extract Layer 3 attacks by target locations."""
    data = fetch_api_data("attacks/layer3/top/locations/target", {"name": "top_0"})
    if data:
        df = process_layer3_attacks_data(data, "layer3_target_attacks")
        save_to_csv(df, "layer3_target_attacks")

def extract_layer3_origin_locations():
    """Extract Layer 3 attacks by origin locations."""
    data = fetch_api_data("attacks/layer3/top/locations/origin", {"name": "top_0"})
    if data:
        df = process_layer3_attacks_data(data, "layer3_origin_attacks")
        save_to_csv(df, "layer3_origin_attacks")

def extract_layer7_origin_locations():
    """Extract Layer 7 attacks by origin locations."""
    data = fetch_api_data("attacks/layer7/top/locations/origin", {"name": "top_0"})
    if data:
        df = process_layer7_attacks_data(data, "layer7_origin_attacks")
        save_to_csv(df, "layer7_origin_attacks")

def extract_http_version_data():
    """Extract HTTP requests by HTTP version."""
    http_versions = ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"]
    for version in http_versions:
        version_key = version.replace("/", "_").lower()
        endpoint = f"http/top/locations/http_version/{version}"
        params = {"metric": f"http_version/{version}"}
        data = fetch_api_data(endpoint, params)
        if data:
            df = process_top_locations_data(data, f"{version_key}_requests")
            save_to_csv(df, f"http_by_{version_key}")

def extract_device_type_data():
    """Extract HTTP requests by device type."""
    device_types = ["desktop", "mobile", "tablet", "other"]
    for device in device_types:
        endpoint = f"http/top/locations/device_type/{device}"
        params = {"metric": f"device_type/{device}"}
        data = fetch_api_data(endpoint, params)
        if data:
            df = process_top_locations_data(data, f"{device}_requests")
            save_to_csv(df, f"http_by_device_{device}")



def update_master_warehouse():
    """Combine all datasets into a master warehouse file, merging on country_code_iso2, using summed attack columns."""
    ensure_directory_exists()
    all_dfs = {}

    for filename in os.listdir(WAREHOUSE_DIR):
        if filename.endswith(".csv") and filename not in ["cloudflare_master_warehouse.csv", "cloudflare_master_warehouse_iso3.csv", "cloudflare_african_countries.csv"]:
            filepath = os.path.join(WAREHOUSE_DIR, filename)
            try:
                df = pd.read_csv(filepath)
                logging.debug(f"Columns in {filename}: {df.columns.tolist()}")
                dataset_name = filename.replace(".csv", "")
                
                # Drop original attack columns, keep only summed columns
                if dataset_name == "layer7_target_attacks_from_top" and "layer7_target_attack_sum" in df.columns:
                    df = df.drop(columns=["layer7_top_target_attacks"], errors="ignore")
                    logging.info(f"Dropped 'layer7_top_target_attacks' from {dataset_name}, keeping 'layer7_target_attack_sum'")
                elif dataset_name == "layer7_origin_attacks_from_top" and "layer7_origin_attack_sum" in df.columns:
                    df = df.drop(columns=["layer7_top_origin_attacks"], errors="ignore")
                    logging.info(f"Dropped 'layer7_top_origin_attacks' from {dataset_name}, keeping 'layer7_origin_attack_sum'")
                elif dataset_name == "layer3_top_origin_attacks" and "layer3_origin_attacks_sum" in df.columns:
                    df = df.drop(columns=["layer3_attacks"], errors="ignore")
                    logging.info(f"Dropped 'layer3_attacks' from {dataset_name}, keeping 'layer3_origin_attacks_sum'")

                if not df.empty:
                    all_dfs[dataset_name] = df
                    logging.info(f"Loaded {dataset_name} with columns: {df.columns.tolist()}")
                else:
                    logging.warning(f"Skipping empty file: {filepath}")
            except pd.errors.EmptyDataError:
                logging.warning(f"Skipping empty file: {filepath}")
            except Exception as e:
                logging.error(f"Error reading {filepath}: {str(e)}")

    if not all_dfs:
        logging.info("No valid datasets to combine into master warehouse")
        return

    base_key = "http_requests_total" if "http_requests_total" in all_dfs else next(iter(all_dfs))
    master_df = all_dfs[base_key][["country_code_iso2", "country_name"]].drop_duplicates().set_index("country_code_iso2")

    for dataset_name, df in all_dfs.items():
        logging.debug(f"Merging {dataset_name} with columns: {df.columns.tolist()}")
        if "country_code_iso2" not in df.columns and "target_country_code_iso2" in df.columns:
            df = df.rename(columns={"target_country_code_iso2": "country_code_iso2", "target_country_name": "country_name"})
            logging.info(f"Converted legacy {dataset_name} to use country_code_iso2")

        metric_cols = [col for col in df.columns if col not in ["country_code_iso2", "country_name"]]
        if metric_cols:
            master_df = master_df.merge(
                df[["country_code_iso2"] + metric_cols],
                how="outer",
                left_index=True,
                right_on="country_code_iso2"
            ).set_index("country_code_iso2")
        elif dataset_name == "internet_quality":
            master_df = master_df.merge(
                df.set_index("country_code_iso2"),
                how="outer",
                left_index=True,
                right_index=True
            )

    master_df["timestamp"] = datetime.now().isoformat()
    master_df = master_df.reset_index()

    if "country_name" in master_df.columns:
        mask = master_df["country_name"].str.lower() == "namibia"
        if mask.any():
            master_df.loc[mask, "country_code_iso2"] = "NA"
            logging.info(f"Enforced country_code_iso2 NA for Namibia based on country_name")

    dataset_cols = [col for col in master_df.columns if col not in ["country_code_iso2", "country_name", "timestamp"]]
    master_df = master_df[["country_code_iso2", "country_name", "timestamp"] + sorted(dataset_cols)]
    save_to_csv(master_df, "cloudflare_master_warehouse")





def convert_to_iso3():
    """Convert country codes in master warehouse from ISO 2 to ISO 3."""
    try:
        df = pd.read_csv(MASTER_WAREHOUSE_FILE)
        if "country_code_iso2" not in df.columns:
            logging.error("No country_code_iso2 column found in master warehouse")
            return

        def get_iso3(row):
            iso2 = row["country_code_iso2"]
            country_name = row.get("country_name")
            if pd.isna(country_name):
                if pd.isna(iso2) or iso2 == "Unknown":
                    return "Unknown"
                try:
                    country = pycountry.countries.get(alpha_2=iso2)
                    return country.alpha_3 if country else "Unknown"
                except Exception as e:
                    logging.warning(f"Could not convert {iso2} to ISO 3: {str(e)}")
                    return "Unknown"
            elif country_name.lower() == "namibia":
                logging.info(f"Manually set country_code_iso3 to NAM for Namibia")
                return "NAM"
            if pd.isna(iso2) or iso2 == "Unknown":
                return "Unknown"
            try:
                country = pycountry.countries.get(alpha_2=iso2)
                return country.alpha_3 if country else "Unknown"
            except Exception as e:
                logging.warning(f"Could not convert {iso2} to ISO 3: {str(e)}")
                return "Unknown"

        df["country_code_iso3"] = df.apply(get_iso3, axis=1)
        df.loc[df["country_code_iso3"] == "NAM", "country_code_iso2"] = "NA"
        logging.info(f"Verified country_code_iso2 set to NA where country_code_iso3 is NAM")

        cols = ["country_code_iso3", "country_code_iso2", "country_name", "timestamp"] + [col for col in df.columns if col not in ["country_code_iso3", "country_code_iso2", "country_name", "timestamp"]]
        df = df[cols]
        save_to_csv(df, "cloudflare_master_warehouse_iso3")
    except Exception as e:
        logging.error(f"Error converting to ISO 3: {str(e)}")




# def extract_african_countries():
#     """Extract data for African countries from ISO 3 warehouse."""
#     try:
#         df = pd.read_csv(MASTER_WAREHOUSE_ISO3_FILE)
#         if "country_code_iso3" not in df.columns:
#             logging.error("No country_code_iso3 column found in ISO 3 warehouse")
#             return

#         african_df = df[df["country_code_iso3"].isin(AFRICAN_COUNTRIES_ISO3)].copy()
#         if african_df.empty:
#             logging.warning("No African countries found in the dataset")
#         else:
#             mask = african_df["country_code_iso3"] == "NAM"
#             if mask.any():
#                 african_df.loc[mask, "country_code_iso2"] = "NA"
#                 logging.info(f"Enforced country_code_iso2 NA for Namibia in African countries dataset")
#             save_to_csv(african_df, "cloudflare_african_countries")
#     except Exception as e:
#         logging.error(f"Error extracting African countries: {str(e)}")
def extract_african_countries():
    """Extract data for African countries from ISO 3 warehouse."""
    try:
        df = pd.read_csv(MASTER_WAREHOUSE_ISO3_FILE)
        logging.debug(f"Loaded master warehouse ISO3 file with {len(df)} rows")
        if "country_code_iso3" not in df.columns:
            logging.error("No country_code_iso3 column found in ISO 3 warehouse")
            return

        african_df = df[df["country_code_iso3"].isin(AFRICAN_COUNTRIES_ISO3)].copy()
        logging.debug(f"Filtered African countries: {len(african_df)} rows")
        if african_df.empty:
            logging.warning("No African countries found in the dataset")
        else:
            mask = african_df["country_code_iso3"] == "NAM"
            if mask.any():
                african_df.loc[mask, "country_code_iso2"] = "NA"
                logging.info(f"Enforced country_code_iso2 NA for Namibia in African countries dataset")
            save_to_csv(african_df, "cloudflare_african_countries")
    except Exception as e:
        logging.error(f"Error extracting African countries: {str(e)}")



def african_country_name_updater():
    """Update country names in cloudflare_african_countries.csv based on country_code_iso3."""
    try:
        df = pd.read_csv(AFRICAN_COUNTRIES_FILE)
        if "country_code_iso3" not in df.columns:
            logging.error("No country_code_iso3 column found in cloudflare_african_countries.csv")
            return

        def get_country_name(iso3):
            if pd.isna(iso3) or iso3 == "Unknown":
                return "Unknown"
            try:
                country = pycountry.countries.get(alpha_3=iso3)
                if country:
                    return country.name
                else:
                    logging.warning(f"No country name found for ISO3 code: {iso3}")
                    return "Unknown"
            except Exception as e:
                logging.warning(f"Error looking up country name for {iso3}: {str(e)}")
                return "Unknown"

        # Update country_name based on country_code_iso3
        df["country_name"] = df["country_code_iso3"].apply(get_country_name)
        
        # Special case for Namibia
        mask = df["country_code_iso3"] == "NAM"
        if mask.any():
            df.loc[mask, "country_name"] = "Namibia"
            df.loc[mask, "country_code_iso2"] = "NA"
            logging.info("Updated country_name to 'Namibia' and country_code_iso2 to 'NA' for NAM")

        save_to_csv(df, "cloudflare_african_countries")
        logging.info("Updated country names in cloudflare_african_countries.csv")
    except Exception as e:
        logging.error(f"Error in african_country_name_updater: {str(e)}")


# def sum_layer7_attacks(csv_file):
#     # Read the CSV
#     df = pd.read_csv(csv_file, sep='\t')  # Adjust separator if needed

#     # Function to sum the values in 'layer7_top_target_attacks'
#     def sum_attacks(attack_str):
#         if pd.isna(attack_str):
#             return 0.0
#         numbers = []
#         num = ''
#         for ch in attack_str:
#             if ch.isdigit() or ch == '.':
#                 num += ch
#             else:
#                 if num:
#                     numbers.append(float(num))
#                     num = ''
#         if num:
#             numbers.append(float(num))
#         return sum(numbers)

#     # Add a new column with the summed values
#     df['attack_sum'] = df['layer7_top_target_attacks'].apply(sum_attacks)

#     # Save it back to the same file (overwrite)
#     df.to_csv(csv_file, sep='\t', index=False)
# --------------------------------------------- THESE SCRIPTS SUM THE COLUMNS FROM CSVs THAT HAVE multiple values ---------------------------------------

def sum_layer7_attacks(csv_file):
    try:
        # Read the CSV file
        df = pd.read_csv(csv_file)
        print(f"Columns in {csv_file}: {df.columns}")  # Debugging: Print column names

        if 'layer7_top_target_attacks' in df.columns:
            def sum_attacks(attack_str):
                if pd.isna(attack_str):
                    return 0.0
                # Use regex to extract numbers starting with '0.'
                import re
                numbers = [float(num) for num in re.findall(r'0\.\d+', attack_str)]
                return sum(numbers)

            # Apply the function to calculate the sum
            df['layer7_target_attack_sum'] = df['layer7_top_target_attacks'].apply(sum_attacks)
            df.to_csv(csv_file, index=False)
            logging.info(f"Updated file with attack_sum: {csv_file}")
        else:
            logging.error(f"'layer7_top_target_attacks' column not found in {csv_file}")
    except Exception as e:
        logging.error(f"Error processing {csv_file}: {str(e)}")

def sum_layer7_origin_attacks_from_top(csv_file):
    try:
        # Read the CSV file
        df = pd.read_csv(csv_file)
        print(f"Columns in {csv_file}: {df.columns}")  # Debugging: Print column names

        if 'layer7_top_origin_attacks' in df.columns:
            def sum_attacks(attack_str):
                if pd.isna(attack_str):
                    return 0.0
                # Use regex to extract numbers starting with '0.'
                import re
                numbers = [float(num) for num in re.findall(r'0\.\d+', attack_str)]
                return sum(numbers)

            # Apply the function to calculate the sum
            df['layer7_origin_attack_sum'] = df['layer7_top_origin_attacks'].apply(sum_attacks)
            df.to_csv(csv_file, index=False)
            logging.info(f"Updated file with attack_sum: {csv_file}")
        else:
            logging.error(f"'layer7_top_origin_attacks' column not found in {csv_file}")
    except Exception as e:
        logging.error(f"Error processing {csv_file}: {str(e)}")
        
def sum_layer3_top_origin_attacks(csv_file):
    try:
        # Read the CSV file
        df = pd.read_csv(csv_file)
        print(f"Columns in {csv_file}: {df.columns}")  # Debugging: Print column names

        if 'layer3_attacks' in df.columns:
            def sum_attacks(attack_str):
                if pd.isna(attack_str):
                    return 0.0
                # Use regex to extract numbers starting with '0.'
                import re
                numbers = [float(num) for num in re.findall(r'0\.\d+', attack_str)]
                return sum(numbers)

            # Apply the function to calculate the sum
            df['layer3_origin_attacks_sum'] = df['layer3_attacks'].apply(sum_attacks)
            df.to_csv(csv_file, index=False)
            logging.info(f"Updated file with attack_sum: {csv_file}")
        else:
            logging.error(f"'layer3_top_origin_attacks' column not found in {csv_file}")
    except Exception as e:
        logging.error(f"Error processing {csv_file}: {str(e)}")


def african_country_nan_filler():
    """Replace NaN values with 0 in numerical columns of cloudflare_african_countries.csv."""
    try:
        df = pd.read_csv(AFRICAN_COUNTRIES_FILE)
        if df.empty:
            logging.warning("cloudflare_african_countries.csv is empty, nothing to fill")
            return

        # Identify numerical columns (float64, int64)
        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
        
        if not numeric_cols.empty:
            # Fill NaN with 0 in numerical columns
            df[numeric_cols] = df[numeric_cols].fillna(0)
            logging.info(f"Filled NaN with 0 in numerical columns: {list(numeric_cols)}")
        else:
            logging.info("No numerical columns found to fill NaN values")

        save_to_csv(df, "cloudflare_african_countries")
        logging.info("Filled NaN values in cloudflare_african_countries.csv")
    except Exception as e:
        logging.error(f"Error in african_country_nan_filler: {str(e)}")

if __name__ == "__main__":
    ensure_directory_exists()
    logging.info("Starting Cloudflare Radar data extraction...")
    # From cloudflare_datasets.py
    extract_http_requests()
    extract_network_traffic()
    extract_dns_queries()
    extract_internet_quality()
    extract_top_domains()
    extract_email_security()
    extract_tcp_resets_timeouts()
    extract_browser_usage()
    extract_os_usage()
    extract_bot_class_data()
    extract_layer7_top_attacks_split()
    extract_layer3_top_origin_attacks()
    extract_layer7_target_locations()
    extract_layer3_target_locations()
    extract_layer3_origin_locations()
    extract_layer7_origin_locations()
    sum_layer7_attacks('../all_datasets/cloudflare_data/layer7_target_attacks_from_top.csv')
    sum_layer7_origin_attacks_from_top('../all_datasets/cloudflare_data/layer7_origin_attacks_from_top.csv')
    sum_layer3_top_origin_attacks('../all_datasets/cloudflare_data/layer3_top_origin_attacks.csv')


    extract_http_version_data()
    extract_device_type_data()
    extract_outages()
    # extract_outages_location()
    # Update warehouse
    update_master_warehouse()
    convert_to_iso3()
    extract_african_countries()
    # New functions for African countries
    african_country_name_updater()
    african_country_nan_filler()
    logging.info("Data extraction, warehouse update, ISO 3 conversion, African countries extraction, and post-processing complete!")