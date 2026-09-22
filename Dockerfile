FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Mount a repository at /repo (and vendored actions at /actions if you have them):
#   docker run --rm -v "$PWD:/repo" taint-trail /repo
ENTRYPOINT ["taint-trail"]
CMD ["--help"]
