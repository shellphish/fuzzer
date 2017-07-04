#!/bin/bash -x

echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
echo core | sudo tee /proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor
