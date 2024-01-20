ID="588858017614048"
LOG_FILE_NAME="5_Req_Async_MultiHost_XLP_6.log"

echo "Preprocess 2 generate log.json"
sed 's/^/{/' $LOG_FILE_NAME | sed 's/$/}/' > log.json
{ echo "["; cat log.json; echo "]"; } > log.json.bak

rm log.json
mv log.json.bak log.json
sed 's/Host \([0-9]\+\)/"Host \1"/g' log.json > log.json.bak

#function comment() {
sed 's/},}/}},/g' log.json.bak > log.json
sed ':a;N;$!ba;s/}},\n\]/}}]/g' log.json > log.json.bak
rm log.json
mv log.json.bak log.json

grep $ID log.json > log.json.bak

echo "" > log.json.bak.bak
while IFS= read -r line; do
    # Execute your commands on each line
    json_str="${line%,}"
    host_pid=$(echo "$line" | jq -r --arg regex "$regex_pattern" '. as $input | keys[] | select(test($regex)) | $input[.] | .event_context.task_context.host_pid')
    host_tid=$(echo "$line" | jq -r --arg regex "$regex_pattern" '. as $input | keys[] | select(test($regex)) | $input[.] | .event_context.task_context.host_tid')
    search_str="\"host_pid\" :  "${host_pid}", \"host_tid\" :  "${host_tid}","
    
    echo "$search_str" >> log.json.bak.bak

done < log.json.bak
grep -v '^$' log.json.bak.bak > log.json.bak
uniq log.json.bak > log.json.bak.bak
echo "" > alllog.json
while IFS= read -r line; do
  echo "$line"
  grep "$line" log.json >> alllog.json
done < log.json.bak.bak

rm log.json.bak*
#}