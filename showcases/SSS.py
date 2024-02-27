from AsymmetricEncryptions.Protocols import SSS
import secrets

# (3,5) sharing scheme
t, n = 3, 5
secret = b"test"
print(f'Original Secret: {secret}')
# Phase I: Generation of shares
shares = SSS.generate_shares(n, t, secret)
print(f'Shares: {", ".join(str(share) for share in shares)}')
# Phase II: Secret Reconstruction
# Picking t shares randomly for
# reconstruction
pool = secrets.SystemRandom().sample(shares, t)
print(f'Combining shares: {", ".join(str(share) for share in pool)}')
print(f'Reconstructed secret: {SSS.reconstruct_secret(pool)}')