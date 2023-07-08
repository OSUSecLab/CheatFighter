#!/bin/bash

j=0

for i in $(find . -exec file {} \; | grep -i elf | grep -i aarch64 | awk '{print $1}')
do
	filename=${i%:}
	
	number=$( strings $filename | grep "maps" -c)
	
	if [[ $number -gt 0 ]]
	then
	echo $filename 
	echo $(strings $filename | grep "maps")
	echo $(strings $filename | grep '^lib')
	fi
	
done
