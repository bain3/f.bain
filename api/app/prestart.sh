#! /usr/bin/env bash

# Script for starting the worker.py script for managing expired files

nohup python /worker.py > /mount/worker.log &
echo "Exiting prestart.sh and starting gunicorn"