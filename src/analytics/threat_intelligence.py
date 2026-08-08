from pyspark.sql import SparkSession


# ============================================================
# Configuration
# ============================================================

INPUT_PATH = (
    "/home/charay/cybersentinel-data/"
    "processed/cybersentinel_flows"
)

OUTPUT_BASE = (
    "/home/charay/cybersentinel-data/"
    "analytics"
)


# ============================================================
# Spark Session
# ============================================================

def create_spark_session():

    spark = (
    SparkSession.builder
    .master("local[*]")
    .appName("CyberSentinel-Threat-Intelligence")
    .config(
        "spark.sql.warehouse.dir",
        "/home/charay/cybersentinel-data/spark-warehouse"
    )
    .getOrCreate()
)

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# Load Data
# ============================================================

def load_data(spark):

    print("\n[1/9] Loading processed Parquet data...")

    df = spark.read.parquet(INPUT_PATH)

    print(f"Rows loaded: {df.count():,}")
    print(f"Columns loaded: {len(df.columns)}")

    return df


# ============================================================
# Register SQL View
# ============================================================

def register_view(df):

    print("\n[2/9] Creating Spark SQL view...")

    df.createOrReplaceTempView("network_flows")

    print("View created: network_flows")


# ============================================================
# Attack Overview
# ============================================================

def attack_overview(spark):

    print("\n[3/9] Attack overview...")

    result = spark.sql("""
        SELECT
            Label,
            IsAttack,
            COUNT(*) AS Flow_Count,

            ROUND(
                COUNT(*) * 100.0 /
                SUM(COUNT(*)) OVER (),
                4
            ) AS Percentage

        FROM network_flows

        GROUP BY Label, IsAttack

        ORDER BY Flow_Count DESC
    """)

    result.show(truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/attack_overview"
    )


# ============================================================
# Attack Timeline
# ============================================================

def attack_timeline(spark):

    print("\n[4/9] Attack timeline...")

    result = spark.sql("""
        SELECT
            DATE(Timestamp) AS Attack_Date,
            Hour,
            Label,
            COUNT(*) AS Attack_Count

        FROM network_flows

        WHERE IsAttack = 1

        GROUP BY
            DATE(Timestamp),
            Hour,
            Label

        ORDER BY
            Attack_Date,
            Hour,
            Attack_Count DESC
    """)

    result.show(30, truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/attack_timeline"
    )


# ============================================================
# Targeted Port Intelligence
# ============================================================

def targeted_ports(spark):

    print("\n[5/9] Targeted-port intelligence...")

    result = spark.sql("""
        SELECT
            Dst_Port,

            COUNT(*) AS Attack_Count,

            COUNT(DISTINCT Label)
                AS Attack_Types,

            ROUND(
                COUNT(*) * 100.0 /
                SUM(COUNT(*)) OVER (),
                2
            ) AS Attack_Share_Percent,

            ROUND(
                AVG(Flow_Duration),
                2
            ) AS Avg_Flow_Duration

        FROM network_flows

        WHERE IsAttack = 1

        GROUP BY Dst_Port

        ORDER BY Attack_Count DESC

        LIMIT 20
    """)

    result.show(20, truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/targeted_ports"
    )


# ============================================================
# Protocol Intelligence
# ============================================================

def protocol_intelligence(spark):

    print("\n[6/9] Protocol intelligence...")

    result = spark.sql("""
        SELECT
            Protocol,
            Label,

            COUNT(*) AS Flow_Count,

            ROUND(
                AVG(Flow_Duration),
                2
            ) AS Avg_Flow_Duration,

            ROUND(
                AVG(Tot_Fwd_Pkts),
                2
            ) AS Avg_Fwd_Packets,

            ROUND(
                AVG(Tot_Bwd_Pkts),
                2
            ) AS Avg_Bwd_Packets,

            ROUND(
                AVG(TotLen_Fwd_Pkts),
                2
            ) AS Avg_Fwd_Bytes,

            ROUND(
                AVG(TotLen_Bwd_Pkts),
                2
            ) AS Avg_Bwd_Bytes

        FROM network_flows

        WHERE IsAttack = 1

        GROUP BY
            Protocol,
            Label

        ORDER BY Flow_Count DESC
    """)

    result.show(30, truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/protocol_intelligence"
    )


# ============================================================
# Traffic Characteristics
# ============================================================
def traffic_characteristics(spark):

    print("\n[7/9] Traffic characteristics...")

    result = spark.sql("""
        SELECT
            Label,

            COUNT(*) AS Flow_Count,

            ROUND(
                AVG(Flow_Duration),
                2
            ) AS Avg_Flow_Duration,

            ROUND(
                AVG(Tot_Fwd_Pkts),
                2
            ) AS Avg_Fwd_Packets,

            ROUND(
                AVG(Tot_Bwd_Pkts),
                2
            ) AS Avg_Bwd_Packets,

            ROUND(
                AVG(TotLen_Fwd_Pkts),
                2
            ) AS Avg_Fwd_Bytes,

            ROUND(
                AVG(TotLen_Bwd_Pkts),
                2
            ) AS Avg_Bwd_Bytes,

            ROUND(
                AVG(
                    CASE
                        WHEN Flow_Byts_per_s IS NULL
                             OR isnan(Flow_Byts_per_s)
                             OR Flow_Byts_per_s = CAST('Infinity' AS DOUBLE)
                             OR Flow_Byts_per_s = CAST('-Infinity' AS DOUBLE)
                        THEN NULL
                        ELSE Flow_Byts_per_s
                    END
                ),
                2
            ) AS Avg_Bytes_Per_Second,

            ROUND(
                AVG(
                    CASE
                        WHEN Flow_Pkts_per_s IS NULL
                             OR isnan(Flow_Pkts_per_s)
                             OR Flow_Pkts_per_s = CAST('Infinity' AS DOUBLE)
                             OR Flow_Pkts_per_s = CAST('-Infinity' AS DOUBLE)
                        THEN NULL
                        ELSE Flow_Pkts_per_s
                    END
                ),
                2
            ) AS Avg_Packets_Per_Second

        FROM network_flows

        GROUP BY Label

        ORDER BY Flow_Count DESC
    """)

    result.show(truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/traffic_characteristics"
    )

# ============================================================
# Hourly Attack Concentration
# ============================================================

def hourly_attack_concentration(spark):

    print("\n[8/9] Calculating hourly attack concentration...")

    result = spark.sql("""
        SELECT
            Hour,

            COUNT(*) AS Attack_Count,

            COUNT(DISTINCT Label)
                AS Attack_Types,

            ROUND(
                COUNT(*) * 100.0 /
                SUM(COUNT(*)) OVER (),
                2
            ) AS Attack_Share_Percent

        FROM network_flows

        WHERE IsAttack = 1

        GROUP BY Hour

        ORDER BY Attack_Count DESC
    """)

    result.show(24, truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/hourly_attack_concentration"
    )


# ============================================================
# Executive Threat Summary
# ============================================================

def executive_summary(spark):

    print("\n[9/9] Building executive threat summary...")

    result = spark.sql("""
        SELECT

            COUNT(*) AS Total_Flows,

            SUM(
                CASE
                    WHEN IsAttack = 1
                    THEN 1
                    ELSE 0
                END
            ) AS Attack_Flows,

            SUM(
                CASE
                    WHEN IsAttack = 0
                    THEN 1
                    ELSE 0
                END
            ) AS Benign_Flows,

            ROUND(
                SUM(
                    CASE
                        WHEN IsAttack = 1
                        THEN 1
                        ELSE 0
                    END
                ) * 100.0 / COUNT(*),
                4
            ) AS Attack_Rate_Percent,

            COUNT(
                DISTINCT CASE
                    WHEN IsAttack = 1
                    THEN Dst_Port
                END
            ) AS Unique_Attack_Targeted_Ports,

            COUNT(
                DISTINCT Protocol
            ) AS Protocols_Observed,

            COUNT(
                DISTINCT CASE
                    WHEN IsAttack = 1
                    THEN Label
                END
            ) AS Attack_Types

        FROM network_flows
    """)

    result.show(truncate=False)

    result.write.mode("overwrite").parquet(
        f"{OUTPUT_BASE}/executive_summary"
    )


# ============================================================
# Main
# ============================================================

def main():

    spark = create_spark_session()

    try:

        df = load_data(spark)

        register_view(df)

        attack_overview(spark)

        attack_timeline(spark)

        targeted_ports(spark)

        protocol_intelligence(spark)

        traffic_characteristics(spark)

        hourly_attack_concentration(spark)

        executive_summary(spark)

        print("\n" + "=" * 75)
        print("CYBERSENTINEL ANALYTICS V2 COMPLETED SUCCESSFULLY")
        print("=" * 75)

        print(f"\nAnalytics stored at:")
        print(OUTPUT_BASE)

    finally:

        spark.stop()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()