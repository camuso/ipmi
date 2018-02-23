#!/bin/sh

set -e

for i in $(seq 0 100); do
   modprobe ipmi_msghandler
   modprobe ipmi_si
   modprobe -r ipmi_si
   modprobe -r ipmi_msghander
done
echo "If you see this message, the test passed."
