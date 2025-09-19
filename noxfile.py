#!/usr/bin/env -S pdm run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "nox==2025.5.1",
# ]
# ///

# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any, Dict, List, Sequence

import nox

nox.needs_version = ">=2025.5.1"

nox.options.error_on_external_run = True
nox.options.default_venv_backend = "uv|virtualenv"
nox.options.reuse_venv = "yes"

PYPROJECT = nox.project.load_toml()


def install_deps(
    session: nox.Session,
    *,
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    project: bool = True,
) -> None:
    """Helper to install dependencies from a group."""
    if not project and extras:
        msg = "Cannot install extras without also installing the project"
        raise TypeError(msg)

    command: List[str] = [
        "uv",
        "sync",
        "--no-default-groups",
    ]

    env: Dict[str, Any] = {}
    if session.venv_backend != "none":
        command.append(f"--python={session.virtualenv.location}")
        env["UV_PROJECT_ENVIRONMENT"] = str(session.virtualenv.location)

    if extras:
        command.extend([f"--extra={e}" for e in extras])
    if groups:
        command.extend([f"--group={g}" for g in groups])
    if not project:
        command.append("--no-install-project")

    session.run_install(
        *command,
        env=env,
        external=True,
    )


@nox.session
def lint(session: nox.Session) -> None:
    """Check all files for linting errors"""
    install_deps(session, project=False, groups=["tools"])

    session.run("prek", "run", "--all-files", *session.posargs)


@nox.session
def pyright(session: nox.Session) -> None:
    """Run pyright."""
    install_deps(session, project=True, groups=["nox", "typing"])
    env = {
        "PYRIGHT_PYTHON_IGNORE_WARNINGS": "1",
    }
    try:
        session.run("python", "-m", "pyright", *session.posargs, env=env)
    except KeyboardInterrupt:
        session.error("Interrupted!")


if __name__ == "__main__":
    nox.main()
