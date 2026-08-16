import sys
import pyspark
import fastapi
import uvicorn
import streamlit
import pandas
import numpy
try:
    import sklearn
    sk_ver = sklearn.__version__
except Exception:
    sk_ver = "Not installed directly (models serialized via Joblib/Pickle)"
import scapy
import plotly
import pytest

print(f"Python: {sys.version.split()[0]}")
print(f"PySpark: {pyspark.__version__}")
print(f"FastAPI: {fastapi.__version__}")
print(f"Uvicorn: {uvicorn.__version__}")
print(f"Streamlit: {streamlit.__version__}")
print(f"Pandas: {pandas.__version__}")
print(f"NumPy: {numpy.__version__}")
print(f"Scikit-learn: {sk_ver}")
print(f"Scapy: {scapy.__version__}")
print(f"Plotly: {plotly.__version__}")
print(f"PyTest: {pytest.__version__}")
