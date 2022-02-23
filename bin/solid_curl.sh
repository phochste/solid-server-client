#!/bin/bash

METHOD=$1
URL=$2
HEADERS=$(npm run --silent headers ${METHOD} ${URL})

echo "curl ${HEADERS} -X ${METHOD} ${URL}"