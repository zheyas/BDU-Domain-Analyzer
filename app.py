# -*- coding: utf-8 -*-

import argparse

from bdu_analyzer.config import DEFAULT_HOST, DEFAULT_PORT
from bdu_analyzer.webapp import run


def main() -> None:
    parser = argparse.ArgumentParser(description="BDU Domain Analyzer")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    args = parser.parse_args()
    run(args.host, args.port)


if __name__ == "__main__":
    main()

