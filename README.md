# cvelint

CVE records in the [v5 JSON schema](https://github.com/CVEProject/cve-schema/tree/master/schema/v5.0) may include errors that are neither enforceable by a schema, nor validated on the backend in CVE Services when a CVE record is created/updated. This CLI tool aims to validate CVE records for such errors.

## Installation

### Binary Releases

For Linux, Mac OS, or Windows, you can download a binary release [here](https://github.com/mprpic/cvelint/releases).

### Build from Source

```bash
$ git clone https://github.com/mprpic/cvelint; cd cvelint
$ make build
$ ./bin/cvelint -h
```

## Usage

```bash
$ git clone https://github.com/CVEProject/cvelistV5  # Download all CVE v5 records
$ ./cvelint -select E005 -cna redhat ./cvelistV5/cves/2023/
Collected 13501 files; checked 222 files.

CVE-2023-3618 (redhat) -- /home/user/cvelistV5/cves/2023/3xxx/CVE-2023-3618.json
  E005  Incorrect CVSS v3 severity: "high" (should be "medium")

Found 1 error.
$ ./cvelint -show-rules  # Display available validation rules
$ ./cvelint -h  # Display help
```
