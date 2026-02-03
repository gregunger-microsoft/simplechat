---
applyTo: '**'
---
Only update the version when the user explicitly requests a version bump.

Example
Before Code Changes
VERSION = "0.228.002"

After Code Changes
VERSION = "0.228.003"

Only increment the third set of digits

Ensure the version is updated in the following files only when explicitly requested:

config.py