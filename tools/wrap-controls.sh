#!/usr/bash

mkdir x
for file in *.rb; do fold -s -w 85 $file | tee x/$file; done
