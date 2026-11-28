"""Print how many archive members hold the planted control and any 12-byte slice of the secret (stdin).

Nested gzip layers are opened, so a compressed image store cannot hide a match."""
import gzip
import sys
import tarfile

secret, control = sys.stdin.readline().strip().encode(), sys.argv[2].encode()
slices = [secret[i:i + 12] for i in range(len(secret) - 11)]
found = [0, 0]
with tarfile.open(sys.argv[1]) as archive:
    for member in archive:
        if member.isfile():
            data = archive.extractfile(member).read()
            data = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
            found[0] += control in data
            found[1] += any(piece in data for piece in slices)
print(*found)
