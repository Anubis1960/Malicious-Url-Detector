import argparse

import dotenv

from src.app.service.url_analyzer import analyze

dotenv.load_dotenv()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument(
        "--sandbox",
        default="false"
    )

    args = parser.parse_args()
    url = args.url
    sandbox = args.sandbox

    if not url.startswith("http"):
        url = "https://" + url

    analyze(url)


if __name__ == '__main__':
    main()