#! /usr/bin/env bash

nohup python /worker.py > /mount/worker.log &
echo "Exiting prestart.sh and starting gunicorn"