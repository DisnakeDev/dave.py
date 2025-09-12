#!/usr/bin/env -S pdm run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "nox==2025.5.1",
# ]
# ///

# SPDX-License-Identifier: MIT

# thanks disnake

from __future__ import annotations

import pathlib
from typing import Any, Dict, List, Sequence, Tuple

import nox

nox.needs_version = ">=2025.5.1"


nox.options.error_on_external_run = True
nox.options.reuse_venv = "yes"
nox.options.sessions = [
    "lint",
    "check-manifest",
    "slotscheck",
    "pyright",
    "test",
]

PYPROJECT = nox.project.load_toml()

# used to reset cached coverage data once for the first test run only
reset_coverage = True


def install_deps(
    session: nox.Session,
    *,
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    project: bool = True,
) -> None:
    """Helper to install dependencies from a group."""
    if not project and extras:
        raise TypeError("Cannot install extras without also installing the project")

    command: List[str] = [
        "pdm",
        "sync",
        "--fail-fast",
        "--clean-unselected",
    ]

    # see https://pdm-project.org/latest/usage/advanced/#use-nox-as-the-runner
    env: Dict[str, Any] = {
        "PDM_IGNORE_SAVED_PYTHON": "1",
    }

    command.extend([f"-G={g}" for g in (*extras, *groups)])

    if not groups:
        # if no dev groups requested, make sure we don't install any
        command.append("--prod")

    if not project:
        command.append("--no-self")

    session.run_install(
        *command,
        env=env,
        external=True,
    )


@nox.session
def lint(session: nox.Session) -> None:
    """Check all files for linting errors"""
    install_deps(session, project=False, groups=["tools"])

    session.run("pre-commit", "run", "--all-files", *session.posargs)


@nox.session(name="check-manifest")
def check_manifest(session: nox.Session) -> None:
    """Run check-manifest."""
    install_deps(session, project=False, groups=["tools"])
    session.run("check-manifest", "-v")


@nox.session
def pyright(session: nox.Session) -> None:
    """Run pyright."""
    install_deps(
        session,
        project=True,
        extras=["speed", "voice"],
        groups=[
            "test",  # tests/
            "nox",  # noxfile.py
            "docs",  # docs/
            "codemod",  # scripts/
            "typing",  # pyright
        ],
    )
    env = {
        "PYRIGHT_PYTHON_IGNORE_WARNINGS": "1",
    }
    try:
        session.run("python", "-m", "pyright", *session.posargs, env=env)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    nox.main()