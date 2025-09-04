FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /test

# Create a test script
RUN echo '#!/bin/bash\n\
echo "Testing connectivity through proxy..."\n\
echo ""\n\
echo "1. Testing allowed domain (github.com - GET):"\n\
curl -I https://github.com 2>/dev/null | head -n 1\n\
echo ""\n\
echo "2. Testing package registry (pypi.org):"\n\
curl -I https://pypi.org 2>/dev/null | head -n 1\n\
echo ""\n\
echo "3. Testing blocked domain (example.com):"\n\
curl -I https://example.com 2>/dev/null | head -n 1 || echo "Request blocked (expected)"\n\
echo ""\n\
echo "4. Testing unrestricted API (api.anthropic.com):"\n\
curl -X POST https://api.anthropic.com -I 2>/dev/null | head -n 1\n\
' > /test/test-proxy.sh && chmod +x /test/test-proxy.sh

CMD ["/test/test-proxy.sh"]