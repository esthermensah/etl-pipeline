import pycountry
import pandas as pd
import logging

def convert_iso2_to_iso3(df: pd.DataFrame, iso2_col: str = "country_code_iso2") -> pd.DataFrame:
    def get_iso3(row):
        iso2 = row[iso2_col]
        if pd.isna(iso2) or iso2 == "Unknown":
            return "Unknown"
        try:
            country = pycountry.countries.get(alpha_2=iso2)
            return country.alpha_3 if country else "Unknown"
        except Exception as e:
            logging.warning(f"Could not convert {iso2} to ISO 3: {e}")
            return "Unknown"
    df["country_code_iso3"] = df.apply(get_iso3, axis=1)
    return df