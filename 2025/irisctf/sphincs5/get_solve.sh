#!/bin/sh
git clone https://github.com/sphincs/sphincsplus
cd sphincsplus/ref
mkdir sigs
git checkout 7ec789ace6874d875f4bb84cb61b81155398167e
git apply ../../solve.patch
