"""Internal fixed-command GeoTrace worker entry point."""
import argparse
import sys

sys.path.insert(0, "/opt/engine/src")
from wolftrap import geotrace_cli

parser = argparse.ArgumentParser()
geotrace_cli.configure(parser.add_subparsers(dest="command", required=True))
args = parser.parse_args()
sys.exit(args.handler(args))
