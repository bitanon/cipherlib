#!/bin/sh
set -e

file=$1
name=$(basename $file .dart)
exe_name="build/$name"

test_file="test/${name}_test.dart"
if [ -f "$test_file" ]; then
  dart test -p vm "$test_file"
fi

mkdir -p build
dart compile exe "$1" -o "$exe_name"
chmod +x "$exe_name"
"$exe_name" "${@:2}"
