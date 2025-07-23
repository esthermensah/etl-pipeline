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
