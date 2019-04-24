# Installation on Ubuntu/Debian x86_64

GitHub repo:
- https://opendev.org/x/iotronic-lightning-rod

# Create container:
```
docker run -d --privileged \
-v lr_var:/var/lib/iotronic -v lr_le:/etc/letsencrypt/ \
-v lr_nginx:/etc/nginx -v lr_confs:/etc/iotronic/ \
-v /etc/passwd:/etc/passwd -v /etc/shadow:/etc/shadow \
--net=host --restart unless-stopped --name=lightning-rod mdslab/openstack-iotronic-lightning-rod
```
