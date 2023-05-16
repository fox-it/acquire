# Acquire

`acquire` is a tool to quickly gather forensic artifacts from disk images or a live system into a lightweight container.
This makes `acquire` an excellent tool to, among others, speedup the process of digital forensic triage.
It uses `dissect` to gather that information from the raw disk, if possible.

`acquire` gathers artifacts based on modules. These modules are paths or globs on a filesystem which acquire attempts to gather.
Multiple modules can be executed at once, which have been collected together inside a profile.
These profiles (used with `--profile`) are  `full`, `default`, `minimal` and `none`.
Depending on what operating system gets detected, different artifacts are collected.

The most basic usage of `acquire` is as follows:

```bash
user@dissect~$ sudo acquire
```

The tool requires administrative access to read raw disk data instead of using the operating system for file access.
However, there are some options available to use the operating system as a fallback option. (e.g `--fallback` or `--force-fallback`)

For more information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/acquire/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`acquire` is available on [PyPI](https://pypi.org/project/acquire/).

```bash
pip install acquire
```

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/acquire>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
