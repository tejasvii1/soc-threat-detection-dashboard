# Running the detections in Splunk

`detections.spl` rewrites this project's three detection rules as Splunk searches, so the same `logs/auth.log` can be investigated in a real SIEM and the results compared with the dashboard.

## 1. Start Splunk locally

From the project root (pick your own admin password, at least 8 characters):

```bash
docker run -d --name splunk -p 8001:8000 \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='choose-a-password' \
  -v "$PWD/logs:/data/logs:ro" \
  splunk/splunk:latest
```

The two `accept` flags agree to Splunk's license terms, so read them first. Startup takes a few minutes; then open http://localhost:8001 and log in as `admin`.

## 2. Load the log

1. **Settings → Add Data → Monitor → Files & Directories**
2. File: `/data/logs/auth.log`
3. Source type: **New**, named `auth_log`
4. Index: `main`, then **Submit**

Check it loaded (time range **All time**):

```
index=main sourcetype=auth_log | stats count
```

The count should match `wc -l logs/auth.log`.

## 3. Run the detections

Paste each search from `detections.spl` into **Search & Reporting** with the time range set to **All time**.

| Search | Should match the dashboard's |
|---|---|
| Brute force | Brute Force alert (same IP and user) |
| Suspicious IP | Suspicious IP alerts (one row per bad IP) |
| Impossible travel | Impossible Travel alerts (same user and cities) |

## Differences from `detect.py`

- Brute force uses `streamstats time_window=10m`, Splunk's equivalent of the two-pointer sliding window.
- Impossible travel only checks for a country change within 30 minutes; the Python rule also computes haversine distance and required speed.

## Stop Splunk

```bash
docker rm -f splunk
```
