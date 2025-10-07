#!/usr/bin/env python
"""
python lib/hello.py \
    tenant \
    --release release.json \
    --previousRelease previous_release.json
"""
import argparse
import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=["managed", "tenant"],
        help="Mode in which the script is called. It does not have any impact for this script."
    )
    parser.add_argument('-s', '--sec', help='Seconds to sleep', required=True)
    parser.add_argument('-r', '--release', help='Path to current release file. Not used, supported to align the interface.', required=True)
    parser.add_argument('-p', '--previousRelease', help='Path to previous release file. Not used, supported to align the interface.', required=False)
    args = vars(parser.parse_args())

    sec = int(args["sec"])
    print(f"Sleeping for {sec}s")
    time.sleep(sec)
    print("{'message': 'Hello world!'}")
