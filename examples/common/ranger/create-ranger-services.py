# Replaces the image's own bootstrap script, which signs in with the image's
# default admin password: with any other password it fails, and five failed
# sign-ins lock Ranger's admin account for five minutes. tools/setup.py
# creates this example's Trino service instead.
