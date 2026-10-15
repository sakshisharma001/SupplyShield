"""Command-line argument parsing with standard argparse."""
import argparse

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Image Resizer CLI")
    parser.add_argument("--input", required=True, help="Path to input image")
    parser.add_argument("--width", type=int, default=800, help="Target width in pixels")
    parser.add_argument("--height", type=int, default=600, help="Target height in pixels")
    return parser
