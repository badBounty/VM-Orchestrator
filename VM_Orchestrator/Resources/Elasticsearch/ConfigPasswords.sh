#!/usr/bin/expect -f

set timeout -1

spawn /home/elasticsearch/elasticsearch-7.10.2/bin/elasticsearch-setup-passwords interactive

expect "Please confirm that you would like to continue \\\[y/N\\\]"

send -- "y\r"

expect "Enter password for \\\[elastic\\\]: "

send -- "elastic\r"

expect "Reenter password for \\\[elastic\\\]: "

send -- "elastic\r"

expect "Enter password for \\\[apm_system\\\]: "

send -- "apmTest\r"

expect "Reenter password for \\\[apm_system\\\]: "

send -- "apmTest\r"

expect "Enter password for \\\[kibana_system\\\]: "

send -- "kibana\r"

expect "Reenter password for \\\[kibana_system\\\]: "

send -- "kibana\r"

expect "Enter password for \\\[logstash_system\\\]: "

send -- "logstash\r"

expect "Reenter password for \\\[logstash_system\\\]: "

send -- "logstash\r"

expect "Enter password for \\\[beats_system\\\]: "

send -- "beatsSystem\r"

expect "Reenter password for \\\[beats_system\\\]: "

send -- "beatsSystem\r"

expect "Enter password for \\\[remote_monitoring_user\\\]: "

send -- "remoteMon\r"

expect "Reenter password for \\\[remote_monitoring_user\\\]: "

send -- "remoteMon\r"

expect eof