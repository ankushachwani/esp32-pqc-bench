# Compile the PQClean "clean" implementations straight from the repo root, so nothing is copied or edited.
import os
Import("env")

root = os.path.abspath(os.path.join(env["PROJECT_DIR"], ".."))
build = os.path.join("$BUILD_DIR", "pqclean")

kem = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]
sig = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "falcon-512",
       "sphincs-sha2-128f-simple", "sphincs-sha2-128s-simple"]

for d in kem:
    env.BuildSources(os.path.join(build, d), os.path.join(root, "crypto_kem", d, "clean"), "+<*.c>")
for d in sig:
    env.BuildSources(os.path.join(build, d), os.path.join(root, "crypto_sign", d, "clean"), "+<*.c>")

# shared hash code; common/randombytes.c is left out on purpose (src/rng.cpp provides randombytes)
env.BuildSources(os.path.join(build, "common"), os.path.join(root, "common"), "-<*> +<fips202.c> +<sha2.c>")
