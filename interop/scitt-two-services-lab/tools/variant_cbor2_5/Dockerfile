# Deviation from what scittles ships, for this lab only: scittles at 6653ab2d with cbor2 below 6. Its requirement
# cbor2>=5.6.0 is open above, and cbor2 6.2.1 returns the content of a tag as a tuple; pycose 1.1.0 accepts only a
# list (measurement/scittles_cause.txt). The code of scittles is unchanged.
FROM b7lab/scittles:6653ab2d
# /home/scittles/.local belongs to root (copied from the build stage), so install as root into that same base.
USER root
RUN PYTHONUSERBASE=/home/scittles/.local pip install --no-cache-dir --user "cbor2>=5.6.0,<6"
USER scittles
