from pathlib import Path
import pandas as pd

DATA_FILE = Path(
    "data/raw/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
)

print("=" * 70)
print("CyberSentinel Dataset Inspection")
print("=" * 70)

# Read only a small sample
df = pd.read_csv(DATA_FILE, nrows=1000)

print("\n1. Dataset file:")
print(DATA_FILE)

print("\n2. Number of columns:")
print(len(df.columns))

print("\n3. Columns:")
for i, column in enumerate(df.columns, start=1):
    print(f"{i:2}. {column}")

print("\n4. Sample shape:")
print(df.shape)

print("\n5. First 5 records:")
print(df.head())

print("\n6. Data types:")
print(df.dtypes)

print("\n7. Missing values in sample:")
missing = df.isnull().sum()
print(missing[missing > 0])

print("\n8. Possible label columns:")
for column in df.columns:
    if "label" in column.lower() or "attack" in column.lower():
        print(f"   {column}")

print("\n9. Unique values in likely label columns:")

for column in df.columns:
    if "label" in column.lower() or "attack" in column.lower():
        print(f"\n{column}:")
        print(df[column].value_counts(dropna=False))

print("\n" + "=" * 70)
print("Inspection complete.")
print("=" * 70)