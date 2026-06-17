#!/bin/bash
mkdir -p build
cd build
cmake ..
make
./cli-server-tests