# Convenience reconstruction, not the original immutable image digest.
FROM python:3.11-slim-bookworm
RUN python -m pip install --no-cache-dir numpy==1.26.4 biopython==1.83 \
 && python -m pip install --no-cache-dir torch==2.5.1+cpu --index-url https://download.pytorch.org/whl/cpu
ENV PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
WORKDIR /tmp
