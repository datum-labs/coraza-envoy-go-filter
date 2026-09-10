# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/coreruleset/go-ftw:1.3.0

RUN sed -i 's/https/http/' /etc/apk/repositories

RUN apk update && apk add curl

WORKDIR /workspace

# Download CRS. This version must match the ruleset embedded in
# internal/config/coreruleset/ (see SecComponentSignature in
# REQUEST-901-INITIALIZATION.conf). A corpus from a different release
# tests rules the filter does not carry.
# Download CRS
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.0.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v4.25.0.tar.gz --strip-components 1

COPY ./ftw.yml /workspace/ftw.yml
COPY ./overrides.yml /workspace/overrides.yml
COPY ./tests.sh /workspace/tests.sh

RUN chmod +x /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
