"""
spark/spark_processor.py
-------------------------
Apache Spark Big Data Processor for CyberWatch

Use this when your log files have MILLIONS of records and
pandas becomes too slow or runs out of memory.

Install:
    pip install pyspark

Run:
    python spark/spark_processor.py --input data/large_logs.csv
    python spark/spark_processor.py --input data/access.log --format apache
    python spark/spark_processor.py --input data/cicids.csv  --format csv --label-col Label

Output:
    spark_output/threats.csv  — all detected threats
    spark_output/summary.txt  — attack summary report
"""

import argparse
import re
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))


# Apache log regex (same as parser.py but PySpark-compatible)
APACHE_PATTERN = (
    r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+'
    r'(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


def get_spark():
    """Initialize SparkSession. Returns None if PySpark not installed."""
    try:
        from pyspark.sql import SparkSession
        import os
        os.environ.setdefault("SPARK_LOCAL_IP", "127.0.0.1")

        spark = SparkSession.builder \
            .appName("CyberWatch-LogProcessor") \
            .master("local[*]") \
            .config("spark.driver.memory", "2g") \
            .config("spark.sql.shuffle.partitions", "4") \
            .getOrCreate()

        spark.sparkContext.setLogLevel("ERROR")
        print(f"[Spark] Session started. UI: http://localhost:4040")
        return spark
    except ImportError:
        print("[Spark] PySpark not installed. Run: pip install pyspark")
        return None


def process_apache_logs(spark, input_path: str) -> "DataFrame":
    """
    Parse raw Apache log file into a Spark DataFrame with features.
    """
    from pyspark.sql import functions as F
    from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType

    print(f"[Spark] Reading Apache logs from {input_path}...")
    raw = spark.read.text(input_path)

    # Parse each line with regex
    parsed = raw.select(
        F.regexp_extract("value", APACHE_PATTERN, 1).alias("ip"),
        F.regexp_extract("value", APACHE_PATTERN, 3).alias("time_str"),
        F.regexp_extract("value", APACHE_PATTERN, 4).alias("method"),
        F.regexp_extract("value", APACHE_PATTERN, 5).alias("url"),
        F.regexp_extract("value", APACHE_PATTERN, 7).cast("int").alias("status"),
        F.regexp_extract("value", APACHE_PATTERN, 8).alias("size_str"),
        F.regexp_extract("value", APACHE_PATTERN, 10).alias("agent"),
    ).filter(F.col("ip") != "")

    # Feature engineering
    df = parsed \
        .withColumn("size", F.when(F.col("size_str") == "-", 0)
                              .otherwise(F.col("size_str").cast("int"))) \
        .withColumn("is_error",     F.col("status") >= 400) \
        .withColumn("is_auth_fail", F.col("status").isin([401, 403])) \
        .withColumn("login_attempt", F.col("url").rlike("(?i)/(login|signin|admin|wp-login|auth)")) \
        .withColumn("hour", F.hour(
            F.to_timestamp(F.col("time_str"), "dd/MMM/yyyy:HH:mm:ss Z")
        ))

    # Per-IP aggregations
    ip_stats = df.groupBy("ip").agg(
        F.count("*").alias("ip_total_requests"),
        F.sum(F.col("is_error").cast("int")).alias("ip_error_count"),
    ).withColumn("error_rate_ip", F.col("ip_error_count") / F.col("ip_total_requests"))

    df = df.join(ip_stats, on="ip", how="left")
    df = df.withColumn("is_new_ip", F.col("ip_total_requests") == 1)

    print(f"[Spark] Parsed {df.count()} log entries.")
    return df


def process_csv_logs(spark, input_path: str, label_col: str = None) -> "DataFrame":
    """
    Read a structured CSV (e.g. CICIDS 2017) into a Spark DataFrame.
    """
    from pyspark.sql import functions as F

    print(f"[Spark] Reading CSV from {input_path}...")
    df = spark.read.csv(input_path, header=True, inferSchema=True)

    # Strip whitespace from column names (CICIDS has leading spaces)
    for col in df.columns:
        clean = col.strip()
        if clean != col:
            df = df.withColumnRenamed(col, clean)

    # Map CICIDS columns to our feature names
    col_map = {
        "Flow Duration"         : "size",
        "Total Fwd Packets"     : "ip_total_requests",
        "Total Backward Packets": "ip_error_count",
        "Destination Port"      : "status",
        "Flow Packets/s"        : "error_rate_ip",
    }
    for old, new in col_map.items():
        if old in df.columns:
            df = df.withColumnRenamed(old, new)

    # Fill required columns if not present
    for col in ["ip", "hour", "url", "is_error", "is_auth_fail", "login_attempt", "is_new_ip"]:
        if col not in df.columns:
            df = df.withColumn(col, F.lit(0))

    print(f"[Spark] Loaded {df.count()} rows, {len(df.columns)} columns.")
    return df


def detect_threats_spark(df: "DataFrame") -> "DataFrame":
    """
    Apply rule-based threat detection logic using Spark SQL functions.
    Returns df with added 'threat_level' and 'attack_type' columns.
    """
    from pyspark.sql import functions as F

    # Rule flags
    df = df \
        .withColumn("rule_brute_force",
            (F.col("is_auth_fail") == True) & (F.col("ip_error_count") >= 5)) \
        .withColumn("rule_port_scan",
            (F.col("error_rate_ip") > 0.80) & (F.col("ip_total_requests") > 20)) \
        .withColumn("rule_new_suspicious",
            (F.col("is_new_ip") == True) & (F.col("is_error") == True))

    # Attack type
    df = df.withColumn("attack_type",
        F.when(F.col("rule_brute_force"), "brute_force")
         .when(F.col("rule_port_scan"),   "port_scan")
         .when(F.col("rule_new_suspicious"), "unknown")
         .otherwise("—")
    )

    # Threat level
    df = df.withColumn("threat_level",
        F.when(F.col("rule_brute_force") | F.col("rule_port_scan"), "ALERT")
         .when(F.col("rule_new_suspicious") | F.col("is_error"), "WATCH")
         .otherwise("CLEAR")
    )

    return df


def save_output(threats: "DataFrame", output_dir: str = "spark_output"):
    """Write threat records to CSV and print summary."""
    Path(output_dir).mkdir(exist_ok=True)

    # Save as single CSV (coalesce to 1 partition)
    output_path = str(Path(output_dir) / "threats")
    threats.coalesce(1).write.csv(output_path, header=True, mode="overwrite")
    print(f"[Spark] Threats saved → {output_path}/")

    # Summary
    from pyspark.sql import functions as F
    print("\n[Spark] ── Attack Summary ──────────────────────")
    threats.groupBy("threat_level").count().orderBy("count", ascending=False).show()
    threats.filter(F.col("threat_level") != "CLEAR") \
           .groupBy("attack_type").count().orderBy("count", ascending=False).show()


def run(input_path: str, fmt: str = "apache", label_col: str = None,
        output_dir: str = "spark_output"):
    spark = get_spark()
    if spark is None:
        return

    try:
        if fmt == "apache":
            df = process_apache_logs(spark, input_path)
        else:
            df = process_csv_logs(spark, input_path, label_col)

        df = detect_threats_spark(df)

        threats = df.filter(df["threat_level"].isin(["WATCH", "ALERT"]))
        print(f"[Spark] Found {threats.count()} threat entries.")
        save_output(threats, output_dir)

    finally:
        spark.stop()
        print("[Spark] Session stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberWatch Spark Processor")
    parser.add_argument("--input",     required=True,          help="Path to log file or CSV")
    parser.add_argument("--format",    default="apache",        help="apache or csv (default: apache)")
    parser.add_argument("--label-col", default=None,           help="Label column name in CSV (e.g. Label)")
    parser.add_argument("--output",    default="spark_output",  help="Output directory")
    args = parser.parse_args()

    run(args.input, args.format, args.label_col, args.output)
