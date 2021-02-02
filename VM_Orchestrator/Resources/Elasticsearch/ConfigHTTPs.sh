#!/usr/bin/expect -f

set timeout -1

spawn /home/elasticsearch/elasticsearch-7.10.2/bin/elasticsearch-certutil http

expect "Generate a CSR? \\\[y/N\\\]"

send -- "n\r"

expect "Use an existing CA? \\\[y/N\\\]"

send -- "y\r"

expect "CA Path: "

send -- "/home/elasticsearch/elasticsearch-7.10.2/config/certs/elastic-stack-ca.p12\r"

expect "Password for elastic-stack-ca.p12:"

send -- "\r"

expect "For how long should your certificate be valid? \\\[5y\\\]"

send -- "3y\r"

expect "Generate a certificate per node? \\\[y/N\\\]"

send -- "n\r"

expect "When you are done, press <ENTER> once more to move on to the next step.\r"

send -- "localhost\r"

send -- "\r"

expect "Is this correct \\\[Y/n\\\]"

send -- "y\r"

expect "When you are done, press <ENTER> once more to move on to the next step.\r"

send -- "127.0.0.1\r"

send -- "192.168.0.252\r"

send -- "\r"

expect "Is this correct \\\[Y/n\\\]"

send -- "y\r"

expect "Do you wish to change any of these options? \\\[y/N\\\]"

send -- "n\r"

expect "Provide a password for the \\\"http.p12\\\" file:  \\\[<ENTER> for none\\\]"

send -- "\r"

expect "What filename should be used for the output zip file? \\\[/home/elasticsearch/elasticsearch-7.10.2/elasticsearch-ssl-http.zip\\\]"

send -- "\r"

expect eof