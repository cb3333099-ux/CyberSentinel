from pyspark.sql import SparkSession
from pyspark.sql import functions as F


DATA_FILE = (
    "data/raw/"
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
)


def main():

    # ---------------------------------------------------------
    # Create Spark session
    # ---------------------------------------------------------

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName("CyberSentinelDatasetProfiler")
        .getOrCreate()
    )

    # Reduce unnecessary Spark logs
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print("CyberSentinel - Dataset Profile")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load complete CSV using Spark
    # ---------------------------------------------------------

    df = (
        spark.read
        .option("header", True)
        .option("inferSchema", True)
        .csv(DATA_FILE)
    )

    # ---------------------------------------------------------
    # 1. Dataset Schema
    # ---------------------------------------------------------

    print("\n1. Dataset Schema")

    df.printSchema()

    # ---------------------------------------------------------
    # 2. Number of Columns
    # ---------------------------------------------------------

    print("\n2. Number of Columns")

    print(len(df.columns))

    # ---------------------------------------------------------
    # 3. Number of Rows
    # ---------------------------------------------------------

    print("\n3. Number of Rows")

    row_count = df.count()

    print(row_count)

    # ---------------------------------------------------------
    # 4. Label Distribution
    # ---------------------------------------------------------

    print("\n4. Label Distribution")

    (
        df.groupBy("Label")
        .count()
        .orderBy(F.desc("count"))
        .show(100, truncate=False)
    )

    # ---------------------------------------------------------
    # 5. Missing Values
    # ---------------------------------------------------------

    print("\n5. Missing Values")

    null_counts = df.select(
        [
            F.sum(
                F.when(
                    F.col(column).isNull(),
                    1
                ).otherwise(0)
            ).alias(column)
            for column in df.columns
        ]
    )

    null_counts.show(truncate=False)

    # ---------------------------------------------------------
    # 6. Infinite Values
    # ---------------------------------------------------------

    print("\n6. Infinite Value Check")

    numeric_columns = [
        field.name
        for field in df.schema.fields
        if field.dataType.typeName()
        in ["double", "float"]
    ]

    infinite_found = False

    for column in numeric_columns:

        infinite_count = df.filter(
            (F.col(column) == float("inf"))
            | (F.col(column) == float("-inf"))
        ).count()

        if infinite_count > 0:

            infinite_found = True

            print(
                f"{column}: "
                f"{infinite_count} infinite values"
            )

    if not infinite_found:
        print("No infinite values found.")

    # ---------------------------------------------------------
    # 7. Basic Dataset Summary
    # ---------------------------------------------------------

    print("\n7. Dataset Summary")

    print(f"Total rows    : {row_count}")
    print(f"Total columns : {len(df.columns)}")

    # ---------------------------------------------------------
    # Finish
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("Profiling complete.")
    print("=" * 70)

    spark.stop()


if __name__ == "__main__":
    main()