FROM nginx:1.19.3

ENV NGINX_ENTRYPOINT_QUIET_LOGS TRUE

RUN rm /etc/nginx/nginx.conf
COPY docker/nginx/nginx.conf /etc/nginx/

RUN rm /etc/nginx/conf.d/default.conf
COPY docker/nginx/project.conf /etc/nginx/conf.d/
