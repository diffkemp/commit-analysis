#!/usr/bin/python3

import argparse
import contextlib
import os
import re
import shutil
import sys
import subprocess
import tempfile

import git
import yaml


def parse_args():
    parser = argparse.ArgumentParser(
        "Check semantic equality of several commits using DiffKemp.")
    parser.add_argument("repo",
                        help="path to the repository to analyze")
    parser.add_argument("--diffkemp", default="diffkemp",
                        help="path to the DiffKemp executable")
    return parser.parse_args()


def locate_functions(old_commit, new_commit):
    all_matched = True
    functions = set()
    for diff in old_commit.diff(new_commit, create_patch=True):
        diff_str = diff.diff.decode()
        matched = False
        # Make use of git's detection of which function was changed. The diff
        # hunk is of the format:
        #   @@ <information about location> @@ <function> name
        for match in re.finditer(r"^@@.*@@ (?P<function>.*)$", diff_str, re.M):
            if not match.group("function").endswith((",", ")", "{")):
                continue
            if f_match := re.search(r"(^|\s)\*?(?P<name>\S*)\(", match.group("function")):
                matched = True
                functions.add(f_match.group("name"))
        # Sometimes the above is imprecise, e.g., if there is a change at the
        # start of a function, the previous function is reported inside the
        # @@ @@ metadata. Try to look for function definitions in the hunk.
        # The regex is obviously not prefect but should get the job done.
        for match in re.finditer(
                r"""^\s*[+-]?\s*  # diff part
                           (\w+\s+){1,5} # return type and extra keywords
                           \*?(?P<function>\w+)\(  # function name
                           ((\w+\s+)+\*?\w+,\s*)*  # arguments separated by commas
                           ((\w+\s+)+\*?\w+)?  # last possible argument
                           \)?$  # line end
                           """,
                diff_str,
                re.VERBOSE | re.MULTILINE):
            matched = True
            functions.add(match.group("function"))
        if not matched:
            # Skip commits where we can't identify the changed function in
            # all the diff hunks
            all_matched = False
    return all_matched, list(functions)


def create_snapshot(repo, commit, diffkemp, functions, output_dir):
    repo.git.clean("-fdx")
    repo.git.restore(".")
    repo.git.checkout(commit.hexsha)

    kargs = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.check_call(["make", "allmodconfig"], **kargs)
    subprocess.check_call(["scripts/config", "--disable", "CONFIG_RETPOLINE"], **kargs)
    subprocess.check_call(["scripts/config", "--disable", "CONFIG_GCC_PLUGIN_LATENT_ENTROPY"], **kargs)
    subprocess.check_call(
        ["make", "prepare", "EXTRA_CFLAGS=-w -fno-pie -no-pie", "KCFLAGS=-w", "HOSTLDFLAGS=-no-pie"],
        **kargs
    )
    subprocess.check_call(
        ["make", "modules_prepare", "EXTRA_CFLAGS=-w -fno-pie -no-pie", "KCFLAGS=-w", "HOSTLDFLAGS=-no-pie"],
        **kargs
    )

    with tempfile.NamedTemporaryFile("w+t", delete_on_close=False) as fp:
        fp.write("\n".join(functions) + "\n")
        fp.close()
        subprocess.check_call(
            [diffkemp, "build-kernel", repo.working_tree_dir, output_dir, fp.name],
            **kargs
        )


def analyze_commit(args, commit):
    repo = git.Repo(args.repo)
    new_commit = repo.commit(commit)
    old_commit = repo.commit(f"{commit}^")

    snapshot_path = os.path.join(os.getcwd(), "snapshot", commit)
    os.makedirs(snapshot_path, exist_ok=True)

    all_results_path = os.path.join(os.getcwd(), "result")
    os.makedirs(all_results_path, exist_ok=True)
    result_path = os.path.join(all_results_path, commit)
    if os.path.exists(result_path):
        shutil.rmtree(result_path)

    old_snapshot = os.path.join(snapshot_path, "old")
    new_snapshot = os.path.join(snapshot_path, "new")

    all_matched, functions = locate_functions(old_commit, new_commit)
    if not functions:
        return {"verdict": "NO-FUNCTIONS"}

    with contextlib.chdir(args.repo):
        create_snapshot(repo, old_commit, args.diffkemp, functions, old_snapshot)
        create_snapshot(repo, new_commit, args.diffkemp, functions, new_snapshot)

    compare_command = [
        args.diffkemp,
        "compare",
        old_snapshot,
        new_snapshot,
        "--report-stat",
        "-o",
        result_path
    ]
    res = subprocess.run(compare_command, capture_output=True)
    output = res.stdout.decode()
    match = re.search(r"""Equal:\s*(?P<eq>\d+)\s+\(\d+%\)\s*
                                 Not\s+equal:\s*(?P<neq>\d+)\s+\(\d+%\)\s*
                                 \(empty\s+diff\):\s*(?P<empty>\d+)\s+\(\d+%\)\s*
                                 Unknown:\s*(?P<unk>\d+)\s+\(\d+%\)\s*
                                 Errors:\s*(?P<err>\d+)\s+\(\d+%\)""", output, re.VERBOSE)
    if not match:
        raise RuntimeError("Unable to detect the number of equal functions")

    eq = int(match.group("eq"))
    neq = int(match.group("neq"))
    empty = int(match.group("empty"))
    unk = int(match.group("unk"))
    err = int(match.group("err"))

    verdict = "equal" if neq + err == 0 else "not equal"

    function_results = {}
    result_files = os.listdir(result_path)
    for function in functions:
        if f"{function}: unknown" in output:
            diff_type = "unk"
        elif f"{function}: error" in output:
            diff_type = "err"
        elif (os.path.exists(result_path) and
              f"{function}.diff" in result_files):
            diff_type = "neq"
        else:
            diff_type = "eq"
        function_results[function] = diff_type

    return {
        "no_functions": len(functions),
        "eq": eq,
        "neq": neq,
        "empty": empty,
        "unk": unk,
        "err": err,
        "verdict": verdict,
        "confident": all_matched,
        "functions": function_results
    }


def run_analysis(args):
    results = {}
    for commit in sys.stdin:
        commit = commit.strip()
        try:
            results[commit] = analyze_commit(args, commit)
        except subprocess.CalledProcessError:
            results[commit] = {"verdict": "FAIL"}
    yaml.safe_dump(results, sys.stdout)


def main():
    args = parse_args()
    run_analysis(args)


if __name__ == "__main__":
    main()
