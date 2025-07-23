import os
import pandas as pd

def save(df, name, output_dir="data"):
    os.makedirs(output_dir, exist_ok=True)
    df.to_csv(f"{output_dir}/{name}.csv", index=False)
