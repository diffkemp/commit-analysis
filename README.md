# Tool for checking semantic equality of several kernel commits using DiffKemp

Tool for checking semantic equality of several kernel commits using
[DiffKemp](https://github.com/diffkemp/diffkemp/).

## Dependencies

- Python3.12+
- Packages from `requirements.txt`
- DiffKemp + its dependencies
- Project to analyse + its dependencies

## Usage

```bash
python3 analyze.py [--diffkemp PATH-TO-DIFFKEMP] PATH-TO-PROJECT-REPO < COMMIT-LIST.txt
```

- `--diffkemp PATH-TO-DIFFKEMP`: Path to a DiffKemp binary.
- `PATH-TO-PROJECT-REPO`: Path to a locally saved project repository which
  commits should be analysed.
- `COMMITS-LIST.txt`: List of project's commits which should be analysed, each
  commit on a single line.

The tool uses DiffKemp to evaluate changes for each commit.
