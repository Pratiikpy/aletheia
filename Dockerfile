FROM node:22-slim

# Foundry (anvil) for the multi-vector honeypot simulation + git/curl for install
# python3 + pipx for slither-analyzer & solc-select (Contract Audit static-analysis engine)
RUN apt-get update && apt-get install -y curl git ca-certificates python3 python3-pip python3-venv pipx \
    && rm -rf /var/lib/apt/lists/*
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:/root/.local/bin:${PATH}"
# Slither + solc-select via pipx (isolated venvs, CLIs on PATH). Pre-install a modern solc as default.
RUN pipx install slither-analyzer && pipx install solc-select \
    && solc-select install 0.8.20 && solc-select use 0.8.20

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN forge build --root . || true

ENV PORT=8788
EXPOSE 8788
CMD ["npx", "tsx", "src/api/server.ts"]
