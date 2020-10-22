FROM jupyterhub/singleuser:1.2.0dev
# Digest b10b21f3d593
# This is the most recent on 20201022
# It is NOT the "latest" tag. The "latest" tag on 20201022
# is the digest e65267c652a3, which is the 0.9.6 tag!

COPY ./healthcheck_notebook.sh /bin/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s CMD /bin/healthcheck.sh

# docker build -t jupyterhub/singleuser-healthchecked:1.2-20201022 .
# docker build -t registry-sdc.argo.grnet.gr/jupyterhub/singleuser-healthchecked:1.2-20201022 .
# docker push registry-sdc.argo.grnet.gr/jupyterhub/singleuser-healthchecked:1.2-20201022

