share: *.go
	go build .

RUN_USER := uploads

install: share
	id -u $(RUN_USER) > /dev/null || useradd --home-dir /var/lib/share --no-create-home --user-group $(RUN_USER)
	install --owner=$(RUN_USER) --group=$(RUN_USER) -m 0750 -d /var/lib/share
	install --owner=$(RUN_USER) --group=$(RUN_USER) -m 0750 -d /var/lib/share/uploads
	install --owner=$(RUN_USER) --group=$(RUN_USER) -m 0440 admin-secret.txt /var/lib/share
	install --owner=$(RUN_USER) --group=$(RUN_USER) -m 0440 upload-secret.txt /var/lib/share
	install --owner=$(RUN_USER) --group=$(RUN_USER) -m 0440 validation.js /var/lib/share
	./generate-systemd-service.sh > share.service
	install -m 0644 share.service /lib/systemd/system
	install share /usr/local/bin
