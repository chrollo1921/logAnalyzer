# The shared web chat as a container.
#
#   docker build -t sapcx-log-analyzer .
#   docker run -p 8765:8765 \
#     --env-file .env -e SAPCX_LA_SERVER_ACCESS_TOKEN \
#     -e SAPCX_LA_SERVER_ALLOWED_HOSTS='["logs.example.com"]' \
#     sapcx-log-analyzer
#
# .env holds LITELLM_BASE_URL and LITELLM_API_KEY, or ANTHROPIC_API_KEY (see .env.example).
# Put it behind your HTTPS reverse proxy. With company single sign-on in front, set
# SAPCX_LA_SERVER_AUTH=header and make sure only the proxy can reach the container.

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
COPY --from=build /install /usr/local
USER app
ENV PYTHONUNBUFFERED=1 \
    SAPCX_LA_SERVER_AUTH=token
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/healthz', timeout=2)"
# One process: uploads and conversations live in its memory, and it serves many users.
CMD ["sapcx-log-analyzer", "serve", "--host", "0.0.0.0", "--port", "8765"]
