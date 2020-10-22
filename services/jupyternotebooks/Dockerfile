FROM jupyterhub/singleuser:1.2

COPY ./healthcheck_notebook.sh /bin/healthcheck.sh

#HEALTHCHECK /bin/healthcheck.sh
HEALTHCHECK --interval=30s --timeout=10s CMD /bin/healthcheck.sh

# docker build jupyterhub/singleuser-healthchecked:1.2-20200428-1


