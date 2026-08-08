from pyspark.sql import SparkSession
from pyspark.sql import functions as F


# ============================================================
# Configuration
# ============================================================

INPUT_FILE = (
    "data/raw/"
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
)

OUTPUT_PATH = "/home/charay/cybersentinel-data/processed/cybersentinel_flows"


# ============================================================
# Spark Session
# ============================================================

def create_spark_session():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName("CyberSentinel-ETL")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# Load Data
# ============================================================

def load_data(spark):

    print("\n[1/6] Loading raw network-flow data...")

    df = (
        spark.read
        .option("header", True)
        .option("inferSchema", True)
        .csv(INPUT_FILE)
    )

    print(f"Loaded {len(df.columns)} columns.")

    return df


# ============================================================
# Clean Column Names
# ============================================================

def clean_column_names(df):

    print("\n[2/6] Cleaning column names...")

    for column in df.columns:

        clean_name = (
            column
            .strip()
            .replace(" ", "_")
            .replace("/", "_per_")
            .replace("-", "_")
        )

        df = df.withColumnRenamed(column, clean_name)

    return df


# ============================================================
# Clean Numeric Values
# ============================================================

def clean_numeric_values(df):

    print("\n[3/6] Cleaning invalid numeric values...")

    numeric_columns = [
        field.name
        for field in df.schema.fields
        if field.dataType.typeName()
        in ["double", "float"]
    ]

    for column in numeric_columns:

        df = df.withColumn(
            column,
            F.when(
                F.col(column).isin(
                    float("inf"),
                    float("-inf")
                ),
                None
            ).otherwise(F.col(column))
        )

    print(
        f"Processed {len(numeric_columns)} numeric columns."
    )

    return df


# ============================================================
# Timestamp Processing
# ============================================================

def process_timestamp(df):

    print("\n[4/6] Processing timestamps...")

    df = df.withColumn(
        "Timestamp",
        F.to_timestamp(
            F.col("Timestamp"),
            "dd/MM/yyyy HH:mm:ss"
        )
    )

    # Add useful time-based features

    df = df.withColumn(
        "Hour",
        F.hour("Timestamp")
    )

    df = df.withColumn(
        "DayOfWeek",
        F.dayofweek("Timestamp")
    )

    df = df.withColumn(
        "IsWeekend",
        F.when(
            F.dayofweek("Timestamp").isin(1, 7),
            1
        ).otherwise(0)
    )

    return df


# ============================================================
# Label Processing
# ============================================================

def process_labels(df):

    print("\n[5/6] Processing attack labels...")

    # Remove accidental whitespace

    df = df.withColumn(
        "Label",
        F.trim(F.col("Label"))
    )

    # Create binary attack indicator

    df = df.withColumn(
        "IsAttack",
        F.when(
            F.col("Label") == "Benign",
            0
        ).otherwise(1)
    )

    return df


# ============================================================
# Write Processed Data
# ============================================================

def write_data(df):

    print("\n[6/6] Writing processed Parquet data...")

    (
        df.write
        .mode("overwrite")
        .parquet(OUTPUT_PATH)
    )

    print(
        f"Processed data written to: {OUTPUT_PATH}"
    )


# ============================================================
# Validation
# ============================================================

def validate_data(df):

    print("\n" + "=" * 70)
    print("ETL VALIDATION")
    print("=" * 70)

    print("\nRows after ETL:")

    print(df.count())

    print("\nColumns after ETL:")

    print(len(df.columns))

    print("\nAttack distribution:")

    (
        df.groupBy("IsAttack")
        .count()
        .orderBy("IsAttack")
        .show()
    )

    print("\nAttack labels:")

    (
        df.groupBy("Label")
        .count()
        .orderBy(F.desc("count"))
        .show(100, truncate=False)
    )

    print("\nSample processed records:")

    df.select(
        "Timestamp",
        "Dst_Port",
        "Protocol",
        "Flow_Duration",
        "Label",
        "IsAttack",
        "Hour",
        "DayOfWeek",
        "IsWeekend"
    ).show(5, truncate=False)

    print("=" * 70)


# ============================================================
# Main Pipeline
# ============================================================

def main():

    spark = create_spark_session()

    try:

        # Extract
        df = load_data(spark)

        # Transform
        df = clean_column_names(df)

        df = clean_numeric_values(df)

        df = process_timestamp(df)

        df = process_labels(df)

        # Load
        write_data(df)

        # Validate
        validate_data(df)

        print("\nETL pipeline completed successfully! ✅")

    finally:

        spark.stop()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()