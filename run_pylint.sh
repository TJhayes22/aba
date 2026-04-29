#!/bin/bash

echo "Running pylint on ABA source..."
echo ""

if [ -f "venv/bin/activate" ]; then
  echo "Activating virtual environment..."
  source venv/bin/activate
fi

pylint *.py \
  --rcfile=.pylintrc \
  --output-format=text \
  --reports=yes \
  --ignore=tests \
  2>&1 | tee pylint_report.txt

echo ""
echo "Pylint complete. Full report saved to pylint_report.txt"
exit 0
