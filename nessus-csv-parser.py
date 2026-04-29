import argparse
import csv
import sys
from typing import Iterable


SUPPORTED_COLUMNS = (
    "Plugin ID",
    "CVE",
    "CVSS v2.0 Base Score",
    "Risk",
    "Host",
    "Protocol",
    "Port",
    "Name",
    "Synopsis",
    "Description",
    "Solution",
    "See Also",
    "Plugin Output",
    "STIG Severity",
    "CVSS v4.0 Base Score",
    "CVSS v4.0 Base+Threat Score",
    "CVSS v3.0 Base Score",
    "CVSS v2.0 Temporal Score",
    "CVSS v3.0 Temporal Score",
    "VPR Score",
    "EPSS Score",
    "Risk Factor",
    "BID",
    "XREF",
    "MSKB",
    "Plugin Publication Date",
    "Plugin Modification Date",
    "Metasploit",
    "Core Impact",
    "CANVAS",
)


def main() -> None:
    args = parse_args()
    output_fields = args.output_fields or list(SUPPORTED_COLUMNS)
    validate_columns(args.match_field, output_fields)
    validate_filter_args(args.match_field, args.match_values)

    try:
        match_count = write_matches_as_csv(
            iter_matching_rows(
                args.csv_file,
                args.match_field,
                args.match_values,
                output_fields,
            ),
            output_fields,
            args.remove_newlines,
        )
    except FileNotFoundError:
        print(f"error: file not found: {args.csv_file}", file=sys.stderr)
        raise SystemExit(1)
    except csv.Error as err:
        print(f"error: failed to parse csv file: {err}", file=sys.stderr)
        raise SystemExit(1)

    if match_count == 0:
        print("No matches found.", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    supported_columns = ", ".join(SUPPORTED_COLUMNS)
    parser = argparse.ArgumentParser(
        description="Search Nessus CSV export rows and print selected columns as CSV.",
        epilog=f"Supported columns: {supported_columns}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="csv_file",
        required=True,
        help="Nessus CSV export file path.",
    )
    parser.add_argument(
        "-k",
        "--key",
        dest="match_field",
        help="Column to search. If omitted, no filtering is applied.",
    )
    parser.add_argument(
        "-v",
        "--values",
        dest="match_values",
        nargs="+",
        help="One or more space-separated values to match (OR logic).",
    )
    parser.add_argument(
        "-c",
        "--columns",
        dest="output_fields",
        nargs="+",
        help="One or more columns to print. Defaults to all supported columns.",
    )
    parser.add_argument(
        "-n",
        "--remove-newlines",
        action="store_true",
        help="Replace embedded newlines in output field values with spaces.",
    )
    return parser.parse_args()


def validate_columns(match_field: str | None, output_fields: list[str]) -> None:
    supported_columns_set = set(SUPPORTED_COLUMNS)
    if match_field is not None and match_field not in supported_columns_set:
        print(
            f"error: unsupported key column '{match_field}'. See supported columns in --help.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    invalid_columns = [field for field in output_fields if field not in supported_columns_set]
    if invalid_columns:
        invalid = ", ".join(invalid_columns)
        print(
            f"error: unsupported output column(s): {invalid}. See supported columns in --help.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def validate_filter_args(match_field: str | None, match_values: list[str] | None) -> None:
    if match_field is None and match_values is not None:
        print("error: --values requires --key.", file=sys.stderr)
        raise SystemExit(2)

    if match_field is not None and match_values is None:
        print("error: --key requires --values.", file=sys.stderr)
        raise SystemExit(2)


def iter_matching_rows(
    csv_file: str,
    match_field: str | None,
    match_values: list[str] | None,
    output_fields: list[str],
) -> Iterable[dict[str, str]]:
    # newline="" is required for correct csv parsing, including quoted multiline values.
    with open(csv_file, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=",")
        if reader.fieldnames is None:
            return

        required_headers = set(output_fields)
        if match_field is not None:
            required_headers.add(match_field)
        missing_headers = sorted(required_headers - set(reader.fieldnames))
        if missing_headers:
            missing = ", ".join(missing_headers)
            print(f"error: missing required header(s): {missing}", file=sys.stderr)
            raise SystemExit(2)

        match_values_set = set(match_values or [])
        for row in reader:
            if match_field is None or row.get(match_field) in match_values_set:
                yield row


def write_matches_as_csv(
    rows: Iterable[dict[str, str]],
    output_fields: list[str],
    remove_newlines: bool,
) -> int:
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(output_fields)

    match_count = 0
    for row in rows:
        writer.writerow(
            [
                normalize_output_value(row.get(field, ""), remove_newlines)
                for field in output_fields
            ]
        )
        match_count += 1

    return match_count


def normalize_output_value(value: str, remove_newlines: bool) -> str:
    if not remove_newlines:
        return value

    return value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


if __name__ == "__main__":
    main()
