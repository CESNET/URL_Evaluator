#!/usr/bin/bash

if ! ps aux | grep '/data/url_evaluator/evaluator[.]py' > /dev/null; then
    python3 /data/url_evaluator/evaluator.py >> /data/url_evaluator/logs/evaluator.log 2>&1
fi
