# Copyright (c) 2021 Matteo Redaelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="msad",
    version="0.1.2",
    author="Matteo Redaelli",
    author_email="matteo.redaelli@gmail.com",
    description="msad is a library and commandline for interacting with Active Directory",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matteoredaelli/msad",
    packages=setuptools.find_packages(),
    license="GPL",
    entry_points={
        "console_scripts": ["msad=msad.command_line:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=["ldap3", "fire"],
    python_requires=">=3.6",
)
