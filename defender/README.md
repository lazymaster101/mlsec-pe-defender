
docker build -t mydefender .


docker run --rm -it -p 8080:8080 mydefender


python3 tools/batch_scan.py   --dir /path/to/goodware/bundle/   --workers 8   --out-csv /path/to/scan_results_gw.csv

Or

'''
DIR="/path/to/samples"
OUT="/path/to/scan_results.csv"
URL="http://127.0.0.1:8080/"

printf "path,result,status,error\n" > "$OUT"
find "$DIR" -type f -print0 | while IFS= read -r -d '' f; do
  resp=$(curl -sS --max-time 20 -H "Content-Type: application/octet-stream" --data-binary @"$f" "$URL")
  if [ $? -eq 0 ]; then
    # crude JSON extract of {"result":X} without jq
    res=$(printf "%s" "$resp" | sed -n 's/.*"result":[[:space:]]*\\([0-9]\\{1,\\}\\).*/\\1/p')
    if [ -n "$res" ]; then
      printf "%s,%s,ok,\n" "$f" "$res" >> "$OUT"
    else
      printf "%s,,bad_json,%s\n" "$f" "$(printf "%s" "$resp" | tr -d '\n' | tr ',' ';')" >> "$OUT"
    fi
  else
    printf "%s,,error,curl_failed\n" "$f" >> "$OUT"
  fi
done
echo "CSV written to $OUT"
'''


curl -s -X POST   -H "Content-Type: application/octet-stream"   --data-binary @/path/to/samples/ http://127.0.0.1:8080/
