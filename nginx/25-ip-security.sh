#!/bin/sh
set -eu

snapshot=/app/data/.ip-security/active-bans.tsv
rules=/etc/nginx/runtime/ip-security.conf
candidate=/etc/nginx/runtime/ip-security.candidate

render_rules() {
    awk -v now="$(date +%s)" -f /etc/nginx/render-security.awk "$snapshot" > "$candidate"
}

install -d -m 0755 /etc/nginx/runtime
# Web may be running before it publishes its first snapshot. Wait only for the
# file to appear; a present but invalid snapshot must fail immediately.
attempt=0
while [ ! -e "$snapshot" ]; do
    if [ "$attempt" -ge 30 ]; then
        echo 'nginx: initial IP security snapshot unavailable' >&2
        exit 1
    fi
    sleep 1
    attempt=$((attempt + 1))
done
render_rules
mv "$candidate" "$rules"
nginx -t

watch_rules() {
    while [ ! -s /var/run/nginx.pid ]; do sleep 1; done
    master_pid=$(cat /var/run/nginx.pid)
    while kill -0 "$master_pid" 2>/dev/null; do
        if render_rules; then
            if ! cmp -s "$candidate" "$rules"; then
                if /usr/local/bin/frontiercloud-tls-edge security; then
                    echo 'nginx: applied IP security rules'
                else
                    echo 'nginx: rejected IP security update; retaining previous rules' >&2
                fi
            fi
        else
            echo 'nginx: invalid/missing IP security snapshot; retaining previous rules' >&2
        fi
        sleep 1
    done
}

# The container PID namespace stops this helper when its Nginx master exits.
# Only local files are polled; unchanged policies cause no database calls/reload.
watch_rules &
