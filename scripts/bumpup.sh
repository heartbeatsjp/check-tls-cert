#!/bin/sh

gobump up -w version/
if [[ $? -ne 0 ]]; then
  echo "Aborted"
  exit
fi

git add version/version.go
version=$(gobump show -r version)
git commit -m "Release ${version}"
git tag -a ${version} -m "Release ${version}"
git push origin ${version}
exit
