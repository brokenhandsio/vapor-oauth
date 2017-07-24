#!/bin/bash
docker build --tag vapor-oauth .
docker run --rm vapor-oauth
