[![Daily scraper of CISA KEV json](https://github.com/BenjiTrapp/cisa-known-vuln-scraper/actions/workflows/daily-scraper-cisa-kev.yml/badge.svg)](https://github.com/BenjiTrapp/cisa-known-vuln-scraper/actions/workflows/daily-scraper-cisa-kev.yml)

<p align="center">
<img height="200" src="static/cisa.jpg">
<br>Daily scaraping of Known Exploited Vulnerabilities @ CISA
</p>

Mirroring `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`daily and stores it on GitHub, since CISA restricts access and applys rate limites. This simply helps to keep everything at one place, and my automation up and running. 

## How it works
The magic is done with the help of this [GitHub Action](.github/workflows/update.yaml)

## How to consume it

You can simply grep the file and search in it like this:

```bash
# Store file
curl https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json -o cisa-kev.json

# Search by product name
jq -r '.vulnerabilities[] | select(.product == "FTA")' cisa-kev.json

# Search by Product name
jq -r '.vulnerabilities[] | select(.vendorProject == "Progress")' bla.json

# Search by CVE
jq -r '.vulnerabilities[] | select(.cveID == "CVE-2023-34362")' bla.json
```
For integration within Gradle it would look like this:

```groovy

dependencyCheck {
    analyzers {
        knownExploitedURL = "https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json"
    }
}
```

