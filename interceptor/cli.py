"""Installed-package configuration bootstrap; does not start a gateway."""
import argparse
from importlib.resources import files
from pathlib import Path
from importlib.metadata import version


def main():
    parser = argparse.ArgumentParser(prog="evilgum")
    parser.add_argument("--version", action="version", version=version("evilgum"))
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-config", help="Write example policy and empty pins into a new directory")
    init.add_argument("--directory", required=True)
    args = parser.parse_args()
    destination = Path(args.directory)
    destination.mkdir(parents=True, exist_ok=True)
    names = ("config.yaml", "mcp-lock.json")
    if any((destination / name).exists() for name in names):
        parser.error("Refusing to overwrite an existing policy or pins")
    for name in names:
        with (destination / name).open("xb") as stream:
            stream.write(files("interceptor").joinpath("assets", name).read_bytes())
    print("Created example policy and EMPTY pins. Review/configure these before deployment.")


if __name__ == "__main__":
    main()
