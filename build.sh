rm dist/*
python setup.py sdist bdist_wheel
python setup.py install
python -m twine upload -r pypi  dist/*

