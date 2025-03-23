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

### Output

The tool reports about the analysis to stdout, the report is in YAML format:

```yaml
# Result of the comparison for given commit
<commit-SHA>:
  # Result of the comparison - `equal` x `not equal`
  verdict: ...
  # True if all commit diffs were matched to a function otherwise false.
  confident: ...
  # Number of functions detected to be changed in the commit.
  no_functions: ...
  # Number of detected functions evaluated as equal.
  eq: ...
  # Number of detected functions evaluated as not equal.
  neq: ...
  # Number of functions evaluated as empty.
  empty: ...
  # Number of functions which was DiffKemp not able to analyse.
  unk: ...
  # Number of functions which was DiffKemp not able to analyse because error
  # occurred during analysis.
  err: ...
```

The result for commit can sometime contain only the `verdict` field, this
happens when:

- an error occurred during the evaluation -> `verdict: FAIL`
- no functions were detected to be changed -> `verdict: NO-FUNCTIONS`

#### Example of output

```yaml
e17d62fedd10ae56e2426858bd0757da544dbc73:
  confident: true
  empty: 1
  eq: 2
  err: 0
  neq: 2
  no_functions: 5
  unk: 1
  verdict: not equal
```
