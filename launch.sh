docker stop paapi
docker rm paapi
docker run --restart always -d -p 2458:2458 -v /opt/paapi/config:/config -v /opt/paapi/logs:/logs --name paapi power_automate_api
